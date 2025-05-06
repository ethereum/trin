use std::path::PathBuf;

use e2store::{
    e2hs::{BlockTuple, E2HSWriter, HeaderWithProofEntry},
    era1::{BodyEntry, ReceiptsEntry},
};
use futures::StreamExt;
use tracing::info;

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
        let mut block_iter = Box::pin(reader.iter_blocks());

        while let Some(block_data) = block_iter.next().await {
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

            e2hs_writer.append_block_tuple(&block_tuple)?;
        }

        let e2hs_path = e2hs_writer.finish()?;

        info!("Wrote epoch {} to {e2hs_path:?}", self.epoch_index);
        Ok(())
    }
}
