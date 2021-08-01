use trin_state;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    return trin_state::main().await;   
}
