use tracing::info;
use trin_execution::{
    cli::{ExportStateConfig, ImportStateConfig},
    config::StateConfig,
    execution::TrinExecution,
    subcommands::e2ss::{export::StateExporter, import::StateImporter},
};
use trin_utils::dir::create_temp_test_dir;

/// Tests that exporting/importing to/from e2ss files works.
///
/// This test does the following:
/// 1. executes first `blocks` blocks
/// 2. exports state to the e2ss
/// 3. imports state from e2ss file into new directory
/// 4. executes another `blocks` blocks
///
/// Following command can be used to run the test for different number of blocks (e.g. 10000):
///
/// ```
/// BLOCKS=10000 cargo test -p trin-execution --test export_import -- --nocapture
/// ```
#[tokio::test]
#[ignore = "This test downloads data from a remote server"]
async fn execute_export_import_execute() -> anyhow::Result<()> {
    let blocks = std::env::var("BLOCKS")
        .ok()
        .and_then(|var| var.parse::<u64>().ok())
        .unwrap_or(1000);
    info!("Running test for {blocks} blocks");

    let temp_directory = create_temp_test_dir()?;
    let e2ss_dir = temp_directory.path().join("era");
    let dir_1 = temp_directory.path().join("dir_1");
    let dir_2 = temp_directory.path().join("dir_2");

    // 1. execute blocks in dir_1
    let mut trin_execution = TrinExecution::new(&dir_1, StateConfig::default()).await?;
    trin_execution
        .process_range_of_blocks(blocks, /* stop_signal= */ None)
        .await?;
    assert_eq!(trin_execution.next_block_number(), blocks + 1);
    drop(trin_execution);

    // 2. export from dir_1 into e2ss
    let exporter = StateExporter::new(
        ExportStateConfig {
            path_to_e2ss: e2ss_dir,
        },
        &dir_1,
    )
    .await?;
    let e2ss_file = exporter.export()?;
    drop(exporter);

    // 3. import from e2ss into dir_2
    let importer = StateImporter::new(
        ImportStateConfig {
            path_to_e2ss: e2ss_file,
        },
        &dir_2,
    )
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
