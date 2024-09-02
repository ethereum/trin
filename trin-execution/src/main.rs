use clap::Parser;

use revm_primitives::SpecId;
use tracing::info;
use trin_execution::{
    cli::TrinExecutionConfig, execution::State, spec_id::get_spec_block_number,
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
    )
    .await?;

    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.unwrap();
        tx.send(true)
            .await
            .expect("signal ctrl_c should never fail");
    });

    let mut block_number = state.next_block_number();

    let end_block = get_spec_block_number(SpecId::MERGE);
    while block_number < end_block {
        if rx.try_recv().is_ok() {
            state.database.db.flush()?;
            info!(
                "Received SIGINT, stopping execution: {} {}",
                block_number - 1,
                state.get_root()?
            );
            break;
        }

        if block_number == 0 {
            // initialize genesis state processes this block so we skip it
            state.era_manager.lock().await.get_next_block().await?;
            state.initialize_genesis()?;
            block_number = 1;
            continue;
        }
        state
            .process_range_of_blocks(block_number, end_block)
            .await?;
        block_number = state.next_block_number();
    }

    Ok(())
}
