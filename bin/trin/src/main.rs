#![warn(clippy::unwrap_used)]

use ethportal_api::types::network_spec::set_network_spec;
use tracing::error;
use trin::{builder::run_trin_from_trin_config, cli::TrinConfig};
use trin_utils::log::init_tracing_logger;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing_logger();
    let trin_config = TrinConfig::from_cli();
    set_network_spec(trin_config.network.clone());
    let trin_handle = run_trin_from_trin_config(trin_config).await?;

    tokio::signal::ctrl_c()
        .await
        .expect("failed to pause until ctrl-c");

    if let Err(err) = trin_handle.rpc_server_handle.stop() {
        error!(err = %err, "Failed to close RPC server")
    }

    Ok(())
}
