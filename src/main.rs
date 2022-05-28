use trin_core::{cli::TrinConfig, utils::infura::build_infura_project_url_from_env};

use trin::run_trin;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    println!("Launching trin");

    let trin_config = TrinConfig::from_cli();
    let infura_url = build_infura_project_url_from_env();

    let exiter = run_trin(trin_config, infura_url).await?;

    tokio::signal::ctrl_c()
        .await
        .expect("failed to pause until ctrl-c");

    exiter.exit();

    Ok(())
}
