use std::path::PathBuf;

use anyhow::bail;
use e2store::{
    e2hs::{
        BlockTuple, BlockTupleOrIndexEntry, E2HSBlockIndexEntry, E2HSWriter, HeaderWithProofEntry,
        BLOCK_TUPLE_COUNT,
    },
    e2store::types::Entry,
    era1::{BlockIndex, BodyEntry, ReceiptsEntry},
};
use ethportal_api::utils::bytes::hex_encode;
use futures::StreamExt;
use tracing::info;
use trin_validation::constants::EPOCH_SIZE;

use crate::reader::EpochReader;

// The `EpochWriter` struct is responsible for writing an epoch to disk in E2HS format.
pub struct EpochWriter {
    target_dir: PathBuf,
    epoch_index: u64,
}

impl EpochWriter {
    pub fn new(target_dir: PathBuf, epoch_index: u64) -> Self {
        Self {
            target_dir,
            epoch_index,
        }
    }

    pub async fn write_epoch(&self, reader: EpochReader) -> anyhow::Result<()> {
        info!(
            "Writing epoch {} to {:?}",
            self.epoch_index, self.target_dir
        );
        let mut e2hs_writer = E2HSWriter::create(&self.target_dir, self.epoch_index)?;
        let mut block_stream = Box::pin(reader.iter_blocks());

        let mut block_index_offset = e2hs_writer.version.version.length() as u64;
        let mut block_index_indices = vec![];
        let mut block_tuple_count = 0;
        let mut last_block_hash = None;
        while let Some(block_data) = block_stream.next().await {
            let block_data = block_data?;
            info!(
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

            block_index_indices.push(block_index_offset);
            let entry = <[Entry; 3]>::try_from(&block_tuple)?;
            let length = entry.iter().map(|entry| entry.length() as u64).sum::<u64>();
            block_index_offset += length;
            block_tuple_count += 1;

            if block_tuple_count == BLOCK_TUPLE_COUNT {
                last_block_hash = Some(
                    block_tuple
                        .header_with_proof
                        .header_with_proof
                        .header
                        .hash_slow(),
                );
            }

            e2hs_writer.append_entry(&BlockTupleOrIndexEntry::BlockTuple(block_tuple))?;

            // Flush the writer to ensure memory usage is kept low.
            if block_tuple_count % 100 == 0 {
                e2hs_writer.flush()?;
            }
        }
        assert_eq!(block_tuple_count, BLOCK_TUPLE_COUNT);

        e2hs_writer.append_entry(&BlockTupleOrIndexEntry::BlockIndex(
            E2HSBlockIndexEntry::new(BlockIndex {
                starting_number: self.epoch_index * EPOCH_SIZE,
                indices: block_index_indices,
                count: BLOCK_TUPLE_COUNT as u64,
            }),
        ))?;

        let Some(last_block_hash) = last_block_hash else {
            bail!("No last block hash found");
        };
        let short_hash = hex_encode(&last_block_hash[..4]);
        let e2hs_path = e2hs_writer.finish(self.epoch_index, short_hash)?;

        info!("Wrote epoch {} to {e2hs_path:?}", self.epoch_index);
        Ok(())
    }
}
