#![warn(clippy::unwrap_used)]

use ethportal_api::types::cli::TrinConfig;
use tracing::error;
use trin_utils::log::init_tracing_logger;

use trin::run_trin;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing_logger();
    let trin_config = TrinConfig::from_cli();
    let rpc_handle = run_trin(trin_config).await?;

    tokio::signal::ctrl_c()
        .await
        .expect("failed to pause until ctrl-c");

    if let Err(err) = rpc_handle.stop() {
        error!(err = %err, "Failed to close RPC server")
    }

    Ok(())
}
