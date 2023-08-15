use crate::constants::fixture_header_with_proof_1000010;
use crate::utils::wait_for_content;
use crate::Peertest;
use ethportal_api::jsonrpsee::http_client::HttpClient;
use ethportal_api::PossibleHistoryContentValue;
use portal_bridge::bridge::Bridge;
use portal_bridge::mode::BridgeMode;
use tokio::time::{sleep, Duration};
use trin_validation::accumulator::MasterAccumulator;
use trin_validation::oracle::HeaderOracle;

pub async fn test_bridge_json(peertest: &Peertest, target: &HttpClient) {
    let master_acc = MasterAccumulator::default();
    let header_oracle = HeaderOracle::new(master_acc);
    let portal_clients = vec![target.clone()];
    let epoch_acc_path = "validation_assets/epoch_acc.bin".into();
    let mode = BridgeMode::Test("./test_assets/portalnet/bridge_data.json".into());
    // Wait for bootnode to start
    sleep(Duration::from_secs(1)).await;
    let bridge = Bridge::new(mode, portal_clients, header_oracle, epoch_acc_path);
    bridge.launch().await;
    let (content_key, content_value) = fixture_header_with_proof_1000010();
    // Check if the stored content value in bootnode's DB matches the offered
    let response = wait_for_content(&peertest.bootnode.ipc_client, content_key).await;
    let received_content_value = match response {
        PossibleHistoryContentValue::ContentPresent(c) => c,
        PossibleHistoryContentValue::ContentAbsent => panic!("Expected content to be found"),
    };
    assert_eq!(
        content_value, received_content_value,
        "The received content {received_content_value:?}, must match the expected {content_value:?}",
    );
}

pub async fn test_bridge_yaml(peertest: &Peertest, target: &HttpClient) {
    let master_acc = MasterAccumulator::default();
    let header_oracle = HeaderOracle::new(master_acc);
    let portal_clients = vec![target.clone()];
    let epoch_acc_path = "validation_assets/epoch_acc.bin".into();
    let mode = BridgeMode::Test("./test_assets/portalnet/bridge_data.yaml".into());
    // Wait for bootnode to start
    sleep(Duration::from_secs(1)).await;
    let bridge = Bridge::new(mode, portal_clients, header_oracle, epoch_acc_path);
    bridge.launch().await;
    let (content_key, content_value) = fixture_header_with_proof_1000010();
    // Check if the stored content value in bootnode's DB matches the offered
    let response = wait_for_content(&peertest.bootnode.ipc_client, content_key).await;
    let received_content_value = match response {
        PossibleHistoryContentValue::ContentPresent(c) => c,
        PossibleHistoryContentValue::ContentAbsent => panic!("Expected content to be found"),
    };
    assert_eq!(
        content_value, received_content_value,
        "The received content {received_content_value:?}, must match the expected {content_value:?}",
    );
}
