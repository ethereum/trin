use crate::constants::{HISTORY_CONTENT_KEY, HISTORY_CONTENT_VALUE};
use crate::utils::wait_for_content;
use crate::Peertest;
use ethportal_api::jsonrpsee::http_client::HttpClient;
use ethportal_api::PossibleHistoryContentValue;
use ethportal_api::{HistoryContentKey, HistoryContentValue};
use portal_bridge::bridge::Bridge;
use portal_bridge::mode::BridgeMode;
use serde_json::json;
use tokio::time::{sleep, Duration};
use trin_validation::accumulator::MasterAccumulator;
use trin_validation::oracle::HeaderOracle;

pub async fn test_bridge(peertest: &Peertest, target: &HttpClient) {
    let master_acc = MasterAccumulator::default();
    let header_oracle = HeaderOracle::new(master_acc);
    let portal_clients = vec![target.clone()];
    let epoch_acc_path = "validation_assets/epoch_acc.bin".into();
    let mode = BridgeMode::Test("./test_assets/portalnet/bridge_data.json".into());
    // Wait for bootnode to start
    sleep(Duration::from_secs(1)).await;
    let bridge = Bridge::new(mode, portal_clients, header_oracle, epoch_acc_path);
    bridge.launch().await;

    let content_key: HistoryContentKey =
        serde_json::from_value(json!(HISTORY_CONTENT_KEY)).unwrap();
    let content_value: HistoryContentValue =
        serde_json::from_value(json!(HISTORY_CONTENT_VALUE)).unwrap();

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
