use std::path::PathBuf;

use e2store::e2hs::E2HSWriter;
use futures::StreamExt;
use tracing::info;

use super::reader::PeriodReader;

// The `PeriodWriter` struct is responsible for writing an period to disk in E2HS format.
pub struct PeriodWriter {
    target_dir: PathBuf,
    period_index: u64,
}

impl PeriodWriter {
    pub fn new(target_dir: PathBuf, period_index: u64) -> Self {
        Self {
            target_dir,
            period_index,
        }
    }

    pub async fn write_period(&self, reader: PeriodReader) -> anyhow::Result<()> {
        info!(
            "Writing period {} to {:?}",
            self.period_index, self.target_dir
        );
        let mut e2hs_writer = E2HSWriter::create(&self.target_dir, self.period_index)?;
        let mut block_iter = Box::pin(reader.iter_blocks());

        while let Some(block) = block_iter.next().await {
            let block = block?;
            info!("Writing block {}", block.header_with_proof.header.number);
            e2hs_writer.append_block_tuple(&block.into())?;
        }

        let e2hs_path = e2hs_writer.finish()?;

        info!("Wrote period {} to {e2hs_path:?}", self.period_index);
        Ok(())
    }
}
