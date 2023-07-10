use std::sync::Arc;

use light_client::config::client_config::Config;
use light_client::config::networks;
use light_client::consensus::rpc::mock_rpc::MockRpc;
use light_client::consensus::ConsensusLightClient;

async fn setup() -> ConsensusLightClient<MockRpc> {
    let base_config = networks::goerli();
    let config = Config {
        consensus_rpc: String::new(),
        chain: base_config.chain,
        forks: base_config.forks,
        max_checkpoint_age: 123123123,
        ..Default::default()
    };

    let checkpoint =
        hex::decode("1e591af1e90f2db918b2a132991c7c2ee9a4ab26da496bd6e71e4f0bd65ea870").unwrap();

    ConsensusLightClient::new("testdata/", &checkpoint, Arc::new(config)).unwrap()
}

#[tokio::test]
async fn test_sync() {
    let mut client = setup().await;
    client.sync().await.unwrap();

    let head = client.get_header();
    assert_eq!(head.slot, 3818196);

    let finalized_head = client.get_finalized_header();
    assert_eq!(finalized_head.slot, 3818112);
}
