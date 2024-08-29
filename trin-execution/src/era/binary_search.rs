use e2store::{
    e2store::types::{Entry, Header as E2StoreHeader},
    era::{get_beacon_fork, CompressedSignedBeaconBlock, Era, SLOTS_PER_HISTORICAL_ROOT},
    utils::get_era_files,
};
use revm_primitives::SpecId;
use surf::Client;

use crate::spec_id::get_spec_block_number;

use super::{
    constants::FIRST_ERA_EPOCH_WITH_EXECUTION_PAYLOAD,
    types::ProcessedEra,
    utils::{download_raw_era, process_era_file},
};

pub struct EraBinarySearch {}

impl EraBinarySearch {
    /// For era files there isn't really a good way to know which era file has the block we want,
    /// well we could download all of them and check that isn't really feasible. We could also
    /// create a table which maps block numbers to era files, but that would be a lot of work and
    /// would need to be updated every time a new era file is added. So we will just binary
    /// search for the era file which contains the block we want. To make it so we don't have to
    /// download multiple era files because they are very big we will download the first beacon
    /// block estimate which blocks it contains and narrow our search till we find it.
    pub async fn find_era_file(
        http_client: Client,
        block_number: u64,
    ) -> anyhow::Result<ProcessedEra> {
        if block_number < get_spec_block_number(SpecId::MERGE) {
            return Err(anyhow::anyhow!(
                "Block number is too low to be in any era file"
            ));
        }

        let era_links = get_era_files(&http_client).await?;
        let mut start_epoch_index = FIRST_ERA_EPOCH_WITH_EXECUTION_PAYLOAD;
        let mut end_epoch_index =
            *era_links.keys().max().expect("Getting max shouldn't fail") as u64;
        let last_epoch_index = end_epoch_index;

        while start_epoch_index <= end_epoch_index {
            let mid = (start_epoch_index + end_epoch_index) / 2;
            let mid_block = EraBinarySearch::download_first_beacon_block_from_era(
                mid,
                era_links[&mid].clone(),
                http_client.clone(),
            )
            .await?;
            let mid_block_number = mid_block.block.execution_block_number();

            // this is an edge case where the block number is in the last era file, we can't check
            // mid plus 1 so we just manually check the last era file
            if mid + 1 > last_epoch_index as u64 {
                let era_to_check =
                    download_raw_era(era_links[&(mid)].clone(), http_client.clone()).await?;

                let decoded_era = Era::deserialize(&era_to_check)?;
                if decoded_era.contains(block_number) {
                    return process_era_file(era_to_check, mid);
                }
                return Err(anyhow::anyhow!("Block not found in any era file"));
            }

            // minimize the worse case by fetching the first block number of the after mid .era
            let mid_plus_one_block = EraBinarySearch::download_first_beacon_block_from_era(
                mid + 1,
                era_links[&(mid + 1)].clone(),
                http_client.clone(),
            )
            .await?;
            let mid_plus_one_block_number = mid_plus_one_block.block.execution_block_number();

            // There are 2 cases to watch for
            // - if fetching a block from the first era, block_number will be 0
            // - for the rest we fetch the next era files first block so we know what range of
            //   blocks is contained in the mid era file
            if mid_block_number == 0
                || (mid_block_number..mid_plus_one_block_number).contains(&block_number)
            {
                let era_to_check =
                    download_raw_era(era_links[&(mid)].clone(), http_client.clone()).await?;

                let decoded_era = Era::deserialize(&era_to_check)?;
                if decoded_era.contains(block_number) {
                    return process_era_file(era_to_check, mid);
                }
            }

            if mid_block_number < block_number {
                start_epoch_index = mid + 1;
            } else {
                end_epoch_index = mid - 1;
            }
        }

        Err(anyhow::anyhow!("Block not found in any era file"))
    }

    async fn download_first_beacon_block_from_era(
        era_index: u64,
        era_path: String,
        http_client: Client,
    ) -> anyhow::Result<CompressedSignedBeaconBlock> {
        // download first compressed beacon block in era file
        let e2store_header = http_client
            .get(&era_path)
            .header("Range", "bytes=8-15")
            .recv_bytes()
            .await
            .expect("to be able to download e2store header");
        let e2store_header = E2StoreHeader::deserialize(&e2store_header)?;
        let compressed_beacon_block = http_client
            .get(&era_path)
            .header("Range", format!("bytes=8-{}", 15 + e2store_header.length))
            .recv_bytes()
            .await
            .expect("to be able to download compressed beacon block");
        let entry = Entry::deserialize(&compressed_beacon_block)?;

        let slot_index = Self::start_slot_index(era_index);
        let fork = get_beacon_fork(slot_index);

        let beacon_block = CompressedSignedBeaconBlock::try_from(&entry, fork)?;

        Ok(beacon_block)
    }

    fn start_slot_index(era_index: u64) -> u64 {
        (era_index - 1) * SLOTS_PER_HISTORICAL_ROOT as u64
    }
}
