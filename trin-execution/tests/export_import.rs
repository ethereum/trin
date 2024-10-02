use tracing::info;
use tracing_test::traced_test;
use trin_execution::{
    cli::{ExportStateConfig, ImportStateConfig},
    config::StateConfig,
    execution::TrinExecution,
    subcommands::era2::{export::StateExporter, import::StateImporter},
};
use trin_utils::dir::create_temp_test_dir;

/// Tests that exporting/importing to/from era2 files works.
///
/// This test does the following:
/// 1. executes first `blocks` blocks
/// 2. exports state to the era2
/// 3. imports state from era2 file into new directory
/// 4. executes another `blocks` blocks
///
/// Following command can be used to run the test for different number of blocks (e.g. 10000):
///
/// ```
/// BLOCKS=10000 cargo test -p trin-execution --test export_import -- --nocapture
/// ```
#[tokio::test]
#[traced_test]
async fn execute_export_import_execute() -> anyhow::Result<()> {
    let blocks = std::env::var("BLOCKS")
        .ok()
        .and_then(|var| var.parse::<u64>().ok())
        .unwrap_or(1000);
    info!("Running test for {blocks} blocks");

    let temp_directory = create_temp_test_dir()?;
    let era2_dir = temp_directory.path().join("era");
    let dir_1 = temp_directory.path().join("dir_1");
    let dir_2 = temp_directory.path().join("dir_2");

    // 1. execute blocks in dir_1
    let mut trin_execution = TrinExecution::new(&dir_1, StateConfig::default()).await?;
    trin_execution
        .process_range_of_blocks(blocks, /* stop_signal= */ None)
        .await?;
    assert_eq!(trin_execution.next_block_number(), blocks + 1);
    drop(trin_execution);

    // 2. export from dir_1 into era2
    let exporter = StateExporter::new(ExportStateConfig {
        data_dir: Some(dir_1),
        path_to_era2: era2_dir,
    })
    .await?;
    let era2_file = exporter.export()?;
    drop(exporter);

    // 3. import from era2 into dir_2
    let importer = StateImporter::new(ImportStateConfig {
        data_dir: Some(dir_2.clone()),
        path_to_era2: era2_file,
    })
    .await?;
    importer.import().await?;
    drop(importer);

    // 4. execute blocks in dir_2
    let mut trin_execution = TrinExecution::new(&dir_2, StateConfig::default()).await?;
    trin_execution
        .process_range_of_blocks(2 * blocks, /* stop_signal= */ None)
        .await?;
    assert_eq!(trin_execution.next_block_number(), 2 * blocks + 1);
    drop(trin_execution);

    Ok(())
}
