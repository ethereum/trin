#![warn(clippy::unwrap_used)]

use tracing::error;
use trin_types::{cli::TrinConfig, provider::TrustedProvider};

use trin::run_trin;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let trin_config = TrinConfig::from_cli();
    let trusted_provider = TrustedProvider::from_trin_config(&trin_config);
    let rpc_handle = run_trin(trin_config, trusted_provider).await?;

    tokio::signal::ctrl_c()
        .await
        .expect("failed to pause until ctrl-c");

    if let Err(err) = rpc_handle.stop() {
        error!(err = %err, "Failed to close RPC server")
    }

    Ok(())
}
