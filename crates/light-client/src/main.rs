use std::path::PathBuf;

use alloy::primitives::{b256, B256};
use anyhow::Result;
use light_client::{
    config::networks, consensus::rpc::nimbus_rpc::NimbusRpc, database::FileDB, Client,
    ClientBuilder,
};
use tracing::info;

const CONSENSUS_RPC_URL: &str = "http://testing.mainnet.beacon-api.nimbus.team";
const TRUSTED_CHECKPOINT: B256 =
    b256!("0x9c30624f15e4df4e8f819f89db8b930f36b561b7f70905688ea208d22fb0b822");
const FALLBACK_URL: &str = "https://sync-mainnet.beaconcha.in";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Create a new Client Builder
    let mut builder = ClientBuilder::new();

    // Set the network to mainnet
    builder = builder.network(networks::Network::Mainnet);

    // Set the consensus rpc url
    builder = builder.consensus_rpc(CONSENSUS_RPC_URL);

    // Set the checkpoint to the last known checkpoint
    builder = builder.checkpoint(TRUSTED_CHECKPOINT);

    // Set the rpc port
    builder = builder.rpc_port(8544);

    // Set the data dir
    builder = builder.data_dir(PathBuf::from("/tmp/light-client"));

    // Set the fallback service
    builder = builder.fallback(FALLBACK_URL);

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
