use trin_history;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    trin_history::main().await
}
