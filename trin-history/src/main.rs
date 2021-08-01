use trin_history;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    return trin_history::main().await;
}
