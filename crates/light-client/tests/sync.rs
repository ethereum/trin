use std::sync::Arc;

use light_client::{
    config::{client_config::Config, networks},
    consensus::{rpc::mock_rpc::MockRpc, ConsensusLightClient},
};

async fn setup() -> ConsensusLightClient<MockRpc> {
    let base_config = networks::mainnet();
    let config = Config {
        consensus_rpc: String::new(),
        chain: base_config.chain,
        forks: base_config.forks,
        max_checkpoint_age: 123123123,
        ..Default::default()
    };

    let checkpoint =
        hex::decode("c62aa0de55e6f21230fa63713715e1a6c13e73005e89f6389da271955d819bde").unwrap();

    ConsensusLightClient::new("testdata/", &checkpoint, Arc::new(config)).unwrap()
}

#[tokio::test]
async fn test_sync() {
    let mut client = setup().await;
    client.sync().await.unwrap();

    let head = client.get_header();
    assert_eq!(head.slot, 7358726);

    let finalized_head = client.get_finalized_header();
    assert_eq!(finalized_head.slot, 7358656);
}
