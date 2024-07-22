use clap::{command, Parser};

use e2store::era1::BLOCK_TUPLE_COUNT;
use revm_primitives::SpecId;
use tracing::info;
use trin_execution::{
    cli::{TrinExecutionConfig, TrinExecutionSubCommands},
    execution::State,
    spec_id::get_spec_block_number,
    storage::utils::setup_temp_dir,
    subcommands::era2::{StateExporter, StateImporter},
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
        trin_execution_config.clone().into(),
    )
    .await?;

    if let Some(command) = trin_execution_config.command {
        match command {
            TrinExecutionSubCommands::ImportState(import_state) => {
                let mut state_importer = StateImporter::new(state, import_state);
                state_importer.import_state()?;
                info!(
                    "Imported state from era2: {} {}",
                    state_importer.state.block_execution_number() - 1,
                    state_importer.state.get_root()?
                );
                return Ok(());
            }
            TrinExecutionSubCommands::ExportState(export_state) => {
                let mut state_exporter = StateExporter::new(state, export_state);
                let block_number = state_exporter.state.block_execution_number() - 1;
                let header = state_exporter
                    .state
                    .era_manager
                    .lock()
                    .await
                    .get_block_by_number(block_number)
                    .await?
                    .clone();
                state_exporter.export_state(header.header)?;
                return Ok(());
            }
        }
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.unwrap();
        tx.send(true)
            .await
            .expect("signal ctrl_c should never fail");
    });

    let mut block_number = state.block_execution_number();

    let end_block = 15_000_000;
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

        let end =
            ((block_number / (BLOCK_TUPLE_COUNT as u64)) + 86) * (BLOCK_TUPLE_COUNT as u64) - 1;
        let end = std::cmp::min(end, end_block);

        if block_number == 0 {
            state.initialize_genesis()?;
            block_number = 1;
            continue;
        }
        state.process_range_of_blocks(block_number, end).await?;
        block_number = state.block_execution_number();
    }

    Ok(())
}
