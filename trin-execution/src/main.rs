use std::cmp::max;

use anyhow::ensure;
use clap::Parser;
use revm_primitives::{keccak256, SpecId, B256, U256};
use tracing::info;
use trin_execution::{
    cli::{TrinExecutionConfig, TrinExecutionSubCommands},
    era::manager::EraManager,
    evm::{block_executor::BLOCKHASH_SERVE_WINDOW, spec_id::get_spec_block_number},
    execution::TrinExecution,
    storage::utils::setup_temp_dir,
    subcommands::era2::{StateExporter, StateImporter},
};
use trin_utils::log::init_tracing_logger;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    let mut trin_execution = TrinExecution::new(
        directory.map(|temp_directory| temp_directory.path().to_path_buf()),
        trin_execution_config.clone().into(),
    )
    .await?;

    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.unwrap();
        tx.send(true)
            .await
            .expect("signal ctrl_c should never fail");
    });

    if let Some(command) = trin_execution_config.command {
        match command {
            TrinExecutionSubCommands::ImportState(import_state) => {
                let mut state_importer = StateImporter::new(trin_execution, import_state);
                state_importer.import_state()?;

                // insert the last 256 block hashes into the database
                let first_block_hash_to_add = max(
                    0,
                    state_importer.trin_execution.next_block_number() - BLOCKHASH_SERVE_WINDOW,
                );
                let mut era_manager = EraManager::new(first_block_hash_to_add).await?;
                for block_number in
                    first_block_hash_to_add..state_importer.trin_execution.next_block_number()
                {
                    let block = era_manager.get_next_block().await?;
                    ensure!(
                        block.header.number == block_number,
                        "Block number mismatch: {} != {}, well importing state",
                        block.header.number,
                        block_number
                    );
                    state_importer.trin_execution.database.db.put(
                        keccak256(B256::from(U256::from(block_number))),
                        block.header.hash(),
                    )?
                }

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

    let mut block_number = trin_execution.next_block_number();

    let end_block = get_spec_block_number(SpecId::MERGE);
    while block_number < end_block {
        if rx.try_recv().is_ok() {
            trin_execution.database.db.flush()?;
            info!(
                "Received SIGINT, stopping execution: {} {}",
                block_number - 1,
                trin_execution.get_root()?
            );
            break;
        }

        trin_execution.process_range_of_blocks(end_block).await?;
        block_number = trin_execution.next_block_number();
    }

    Ok(())
}
