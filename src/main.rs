use trin_core::cli::TrinConfig;
use trin_core::utils::infura::fetch_infura_id_from_env;

use trin::run_trin;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    println!("Launching trin");

    let trin_config = TrinConfig::from_cli();
    let infura_project_id = fetch_infura_id_from_env();

    let exiter = run_trin(trin_config, infura_project_id).await?;

    tokio::signal::ctrl_c()
        .await
        .expect("failed to pause until ctrl-c");

    exiter.exit();

    Ok(())
}
