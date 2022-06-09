use trin_core::utils::infura::build_infura_project_url_from_env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let infura_url = build_infura_project_url_from_env();
    trin_history::main(infura_url).await
}
