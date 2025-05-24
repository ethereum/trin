mod binary_search;
mod e2hs_builder;
mod provider;

use std::time::Instant;

use e2hs_builder::E2HSBuilder;
use humanize_duration::{prelude::DurationExt, Truncate};
use tracing::info;

use crate::cli::SingleGeneratorConfig;

pub async fn single_generator(config: SingleGeneratorConfig) -> anyhow::Result<()> {
    info!("Running E2HS single writer");
    let start = Instant::now();
    let e2hs_builder = E2HSBuilder::new(
        config.index,
        config.portal_accumulator_path,
        config.el_provider,
    )
    .await?;
    info!(
        "Time taken to download Era/Era1 and Receipts {}",
        start.elapsed().human(Truncate::Second)
    );

    let start = Instant::now();
    e2hs_builder
        .build_e2hs_file(config.target_dir, config.index)
        .await?;
    info!(
        "Time taken to finished writing blocks  {}",
        start.elapsed().human(Truncate::Second)
    );
    Ok(())
}
