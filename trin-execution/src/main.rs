use clap::Parser;
use tracing::info;
use trin_execution::{
    cli::{TrinExecutionConfig, TrinExecutionSubCommands, APP_NAME},
    execution::TrinExecution,
    subcommands::era2::{export::StateExporter, import::StateImporter},
};
use trin_utils::{dir::setup_data_dir, log::init_tracing_logger};

const LATEST_BLOCK: u64 = 20_868_946;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing_logger();

    let trin_execution_config = TrinExecutionConfig::parse();

    let data_dir = setup_data_dir(
        APP_NAME,
        trin_execution_config.data_dir.clone(),
        trin_execution_config.ephemeral,
    )?;

    if let Some(command) = trin_execution_config.command {
        match command {
            TrinExecutionSubCommands::ImportState(import_state_config) => {
                let state_importer = StateImporter::new(import_state_config, &data_dir).await?;
                let header = state_importer.import().await?;
                info!(
                    "Imported state from era2: {} {}",
                    header.number, header.state_root,
                );
                return Ok(());
            }
            TrinExecutionSubCommands::ExportState(export_state_config) => {
                let state_exporter = StateExporter::new(export_state_config, &data_dir).await?;
                state_exporter.export()?;
                info!(
                    "Exported state into era2: {} {}",
                    state_exporter.header().number,
                    state_exporter.header().state_root,
                );
                return Ok(());
            }
        }
    }

    // Initialize prometheus metrics
    if let Some(addr) = trin_execution_config.enable_metrics_with_url {
        prometheus_exporter::start(addr)?;
    }

    let mut trin_execution =
        TrinExecution::new(&data_dir, trin_execution_config.clone().into()).await?;

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.unwrap();
        tx.send(()).expect("signal ctrl_c should never fail");
    });

    let last_block = trin_execution_config.last_block.unwrap_or(LATEST_BLOCK);
    trin_execution
        .process_range_of_blocks(last_block, Some(rx))
        .await?;

    Ok(())
}
