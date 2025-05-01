pub mod provider;
pub mod reader;
pub mod writer;

use std::time::Instant;

use humanize_duration::{prelude::DurationExt, Truncate};
use reader::PeriodReader;
use tracing::info;
use writer::PeriodWriter;

use crate::cli::SingleGeneratorConfig;

pub async fn single_generator(config: SingleGeneratorConfig) -> anyhow::Result<()> {
    info!("Running E2HS single writer");
    let start = Instant::now();
    let period_reader = PeriodReader::new(
        config.period,
        config.portal_accumulator_path,
        config.el_provider,
    )
    .await?;
    info!(
        "Time taken to download Era/Era1 and Receipts {}",
        start.elapsed().human(Truncate::Second)
    );

    let start = Instant::now();
    let period_writer = PeriodWriter::new(config.target_dir, config.period);
    period_writer.write_period(period_reader).await?;
    info!(
        "Time taken to finished writing blocks  {}",
        start.elapsed().human(Truncate::Second)
    );
    Ok(())
}
