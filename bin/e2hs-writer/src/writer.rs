use e2store::{
    e2hs::{BlockTuple, E2HSBlockIndexEntry, HeaderWithProofEntry, BLOCK_TUPLE_COUNT, E2HS},
    e2store::types::{Entry, VersionEntry},
    entry_types::VERSION,
    era1::{BlockIndex, BodyEntry, ReceiptsEntry},
};
use ethportal_api::utils::bytes::hex_encode;
use futures::StreamExt;
use tracing::{debug, info};

use crate::reader::EpochReader;

// The `EpochWriter` struct is responsible for writing an epoch to disk in E2HS format.
pub struct EpochWriter {
    target_dir: String,
    epoch: u64,
}

impl EpochWriter {
    pub fn new(target_dir: String, epoch: u64) -> Self {
        Self { target_dir, epoch }
    }

    pub async fn write_epoch(&self, reader: EpochReader) -> anyhow::Result<()> {
        info!("Writing epoch {} to {}", self.epoch, self.target_dir);
        let mut block_tuples: Vec<BlockTuple> = vec![];
        let mut block_stream = Box::pin(reader.iter_blocks());

        while let Some(Ok(block_data)) = block_stream.next().await {
            debug!(
                "Writing block {}",
                block_data.header_with_proof.header.number
            );
            let header_with_proof = HeaderWithProofEntry {
                header_with_proof: block_data.header_with_proof,
            };
            let body = BodyEntry {
                body: block_data.body,
            };
            let receipts = ReceiptsEntry {
                receipts: block_data.receipts,
            };
            let block_tuple = BlockTuple {
                header_with_proof,
                body,
                receipts,
            };
            block_tuples.push(block_tuple);
        }
        assert_eq!(block_tuples.len(), BLOCK_TUPLE_COUNT);
        let version = VersionEntry {
            version: Entry::new(VERSION, vec![]),
        };
        let mut offset = version.version.length() as u64;
        let mut indices = vec![];
        for block_tuple in &block_tuples {
            indices.push(offset);
            let entry = <[Entry; 3]>::try_from(block_tuple)?;
            let length = entry.iter().map(|entry| entry.length() as u64).sum::<u64>();
            offset += length;
        }
        let starting_header = &block_tuples[0].header_with_proof.header_with_proof.header;
        let ending_header_hash = &block_tuples[BLOCK_TUPLE_COUNT - 1]
            .header_with_proof
            .header_with_proof
            .header
            .hash_slow();
        let block_index = BlockIndex {
            starting_number: starting_header.number,
            indices,
            count: BLOCK_TUPLE_COUNT as u64,
        };
        let block_index = E2HSBlockIndexEntry { block_index };
        let e2hs = E2HS {
            version,
            block_tuples,
            block_index,
        };
        let raw_e2hs = e2hs.write()?;

        let short_hash = hex_encode(&ending_header_hash[..4]);
        let e2hs_path = format!(
            "{}/mainnet-{:05}-{}.e2hs",
            self.target_dir,
            self.epoch,
            short_hash.trim_start_matches("0x")
        );
        std::fs::write(e2hs_path.clone(), raw_e2hs)?;
        info!("Wrote epoch {} to {e2hs_path}", self.epoch);
        Ok(())
    }
}
