use trin_core::{cli::TrinConfig, utils::provider::TrustedProvider};

use trin::run_trin;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    println!("Launching trin");

    let trin_config = TrinConfig::from_cli();
    let trusted_provider = TrustedProvider::from_trin_config(&trin_config);
    let exiter = run_trin(trin_config, trusted_provider).await?;

    tokio::signal::ctrl_c()
        .await
        .expect("failed to pause until ctrl-c");

    exiter.exit();

    Ok(())
}
