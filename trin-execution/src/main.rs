use clap::Parser;

use revm_primitives::SpecId;
use tracing::info;
use trin_execution::{
    cli::TrinExecutionConfig,
    era_manager::EraManager,
    execution::State,
    metrics::{start_timer_vec, stop_timer, BLOCK_PROCESSING_TIMES},
    spec_id::get_spec_block_number,
    storage::utils::setup_temp_dir,
};
use trin_utils::log::init_tracing_logger;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing_logger();

    let trin_execution_config = TrinExecutionConfig::parse();

    // Initialize prometheus metrics
    if let Some(addr) = trin_execution_config.enable_metrics_with_url {
        prometheus_exporter::start(addr)?;
    }

    let directory = match trin_execution_config.ephemeral {
        false => None,
        true => Some(setup_temp_dir()?),
    };

    let mut state = State::new(
        directory.map(|temp_directory| temp_directory.path().to_path_buf()),
        trin_execution_config.into(),
    )?;

    let mut era_manager = EraManager::new().await?;

    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.unwrap();
        tx.send(true)
            .await
            .expect("signal ctrl_c should never fail");
    });

    for block_number in state.block_execution_number()..=get_spec_block_number(SpecId::MERGE) {
        if rx.try_recv().is_ok() {
            state.database.db.flush()?;
            info!(
                "Received SIGINT, stopping execution: {block_number} {}",
                state.get_root()?
            );
            break;
        }

        let timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["fetching_block_from_era"]);
        let block_tuple = era_manager.get_block_by_number(block_number).await?;
        stop_timer(timer);
        let timer = start_timer_vec(&BLOCK_PROCESSING_TIMES, &["processing_block"]);
        if block_tuple.header.header.number == 0 {
            state.initialize_genesis()?;
            continue;
        }
        state.process_block(block_tuple)?;
        stop_timer(timer);
        assert_eq!(state.get_root()?, block_tuple.header.header.state_root);
    }

    Ok(())
}
