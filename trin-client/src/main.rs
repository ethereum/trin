// trin --networks state, history
//  - by default it starts both state and history networks
//
// what to do about network specific kwargs?
// - will different networks use different dht udp ports?
//

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    trin_client::main().await
}
