use clap::Parser;
use revm_primitives::SpecId;
use tracing::info;
use trin_evm::spec_id::get_spec_block_number;
use trin_execution::{
    cli::{TrinExecutionConfig, TrinExecutionSubCommands},
    era::manager::EraManager,
    execution::TrinExecution,
    subcommands::era2::{export::StateExporter, import::StateImporter},
};
use trin_utils::{dir::setup_data_dir, log::init_tracing_logger};

const APP_NAME: &str = "trin-execution";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing_logger();

    let trin_execution_config = TrinExecutionConfig::parse();

    // Initialize prometheus metrics
    if let Some(addr) = trin_execution_config.enable_metrics_with_url {
        prometheus_exporter::start(addr)?;
    }

    let data_dir = setup_data_dir(
        APP_NAME,
        trin_execution_config.data_dir.clone(),
        trin_execution_config.ephemeral,
    )?;

    let mut trin_execution =
        TrinExecution::new(&data_dir, trin_execution_config.clone().into()).await?;

    if let Some(command) = trin_execution_config.command {
        match command {
            TrinExecutionSubCommands::ImportState(import_state) => {
                let mut state_importer = StateImporter::new(trin_execution, import_state);
                state_importer.import_state()?;
                state_importer.import_last_256_block_hashes().await?;

                info!(
                    "Imported state from era2: {} {}",
                    state_importer.trin_execution.next_block_number() - 1,
                    state_importer.trin_execution.get_root()?
                );
                return Ok(());
            }
            TrinExecutionSubCommands::ExportState(export_state) => {
                let mut era_manager =
                    EraManager::new(trin_execution.next_block_number() - 1).await?;
                let header = era_manager.get_next_block().await?.clone();
                let mut state_exporter = StateExporter::new(trin_execution, export_state);
                state_exporter.export_state(header.header)?;
                return Ok(());
            }
        }
    }

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.unwrap();
        tx.send(()).expect("signal ctrl_c should never fail");
    });

    let end_block = get_spec_block_number(SpecId::CANCUN);
    trin_execution
        .process_range_of_blocks(end_block, Some(rx))
        .await?;

    Ok(())
}
