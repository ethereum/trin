pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::spawn(async move {
        println!("Hello, from the history network!");
    })
    .await
    .unwrap();

    Ok(())
}
