use eyre::Result;
use light_client::config::networks;
use light_client::consensus::rpc::nimbus_rpc::NimbusRpc;
use light_client::database::FileDB;
use light_client::{Client, ClientBuilder};
use std::path::PathBuf;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Create a new Client Builder
    let mut builder = ClientBuilder::new();

    // Set the network to mainnet
    builder = builder.network(networks::Network::Mainnet);

    // Set the consensus rpc url
    builder = builder.consensus_rpc("http://testing.mainnet.beacon-api.nimbus.team");

    // Set the checkpoint to the last known checkpoint
    builder =
        builder.checkpoint("0x44389a44d9da9e5e073a7f0bfb19844c2a9aacfafaa81558577ae0e373ec9eb9");

    // Set the rpc port
    builder = builder.rpc_port(8544);

    // Set the data dir
    builder = builder.data_dir(PathBuf::from("/tmp/light-client"));

    // Set the fallback service
    builder = builder.fallback("https://sync-mainnet.beaconcha.in");

    // Enable lazy checkpoints
    builder = builder.load_external_fallback();

    // Build the client
    let mut client: Client<FileDB, NimbusRpc> = builder.build().unwrap();

    info!("Starting consensus light client...");
    // Run the client
    client.start().await.unwrap();

    tokio::signal::ctrl_c()
        .await
        .expect("failed to pause until ctrl-c");

    Ok(())
}
