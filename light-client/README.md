# Consensus Light client

Most of the code in this crate is fork of [Helios](https://github.com/a16z/helios) but it doesn't require running 
an execution client alongside the light client.

This light client is modified in a way to be compatible with Portal Network.

### Running the light client

To run the light client with default configuration and https://www.lightclientdata.org as consensus rpc:

```shell
cd trin
cargo run -p light-client
```

### Using light-client crate as a Library

```rust
use eyre::Result;
use light_client::config::networks;
use light_client::database::FileDB;
use light_client::{Client, ClientBuilder};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    // Create a new Client Builder
    let mut builder = ClientBuilder::new();

    // Set the network to mainnet
    builder = builder.network(networks::Network::Mainnet);

    // Set the consensus rpc url
    builder = builder.consensus_rpc("https://www.lightclientdata.org");

    // Set the checkpoint to the last known checkpoint
    builder =
        builder.checkpoint("0x760387ebbc6d7c48e421424def00cfd85d71dd8f4ea3a9c0bb2f01b684553a6d");

    // Set the rpc port
    builder = builder.rpc_port(8545);

    // Set the data dir
    builder = builder.data_dir(PathBuf::from("/tmp/light-client"));

    // Set the fallback service
    builder = builder.fallback("https://sync-mainnet.beaconcha.in");

    // Enable lazy checkpoints
    builder = builder.load_external_fallback();

    // Build the client
    let mut client: Client<FileDB> = builder.build().unwrap();

    // Run the client
    client.start().await.unwrap();

    tokio::signal::ctrl_c()
        .await
        .expect("failed to pause until ctrl-c");

    Ok(())
}
```