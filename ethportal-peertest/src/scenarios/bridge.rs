use crate::constants::fixture_header_with_proof_1000010;
use crate::utils::{wait_for_beacon_content, wait_for_history_content};
use crate::Peertest;
use ethportal_api::jsonrpsee::http_client::HttpClient;
use ethportal_api::{
    BeaconContentKey, BeaconContentValue, PossibleBeaconContentValue, PossibleHistoryContentValue,
};
use portal_bridge::beacon_bridge::BeaconBridge;
use portal_bridge::bridge::Bridge;
use portal_bridge::consensus_api::ConsensusApi;
use portal_bridge::execution_api::ExecutionApi;
use portal_bridge::mode::BridgeMode;
use portal_bridge::pandaops::PandaOpsMiddleware;
use serde_json::Value;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use trin_validation::accumulator::MasterAccumulator;
use trin_validation::oracle::HeaderOracle;

pub async fn test_history_bridge(peertest: &Peertest, target: &HttpClient) {
    let master_acc = MasterAccumulator::default();
    let header_oracle = HeaderOracle::new(master_acc);
    let portal_clients = vec![target.clone()];
    let epoch_acc_path = "validation_assets/epoch_acc.bin".into();
    let mode = BridgeMode::Test("./test_assets/portalnet/bridge_data.json".into());
    let pandaops_middleware = PandaOpsMiddleware::default();
    let execution_api = ExecutionApi::new(pandaops_middleware);
    // Wait for bootnode to start
    sleep(Duration::from_secs(1)).await;
    let bridge = Bridge::new(
        mode,
        execution_api,
        portal_clients,
        header_oracle,
        epoch_acc_path,
    );
    bridge.launch().await;
    let (content_key, content_value) = fixture_header_with_proof_1000010();
    // Check if the stored content value in bootnode's DB matches the offered
    let response = wait_for_history_content(&peertest.bootnode.ipc_client, content_key).await;
    let received_content_value = match response {
        PossibleHistoryContentValue::ContentPresent(c) => c,
        PossibleHistoryContentValue::ContentAbsent => panic!("Expected content to be found"),
    };
    assert_eq!(
        content_value, received_content_value,
        "The received content {received_content_value:?}, must match the expected {content_value:?}",
    );
}

pub async fn test_beacon_bridge(peertest: &Peertest, target: &HttpClient) {
    let portal_clients = Arc::new(vec![target.clone()]);
    let mode = BridgeMode::Test("./test_assets/portalnet/beacon_bridge_data.yaml".into());
    // Wait for bootnode to start
    sleep(Duration::from_secs(1)).await;
    let consensus_api = ConsensusApi::default();
    let bridge = BeaconBridge::new(consensus_api, mode, portal_clients);
    bridge.launch().await;

    let value = std::fs::read_to_string("./test_assets/portalnet/beacon_bridge_data.yaml")
        .expect("cannot find test asset");
    let value: Value = serde_yaml::from_str(&value).unwrap();
    let content_key: BeaconContentKey =
        serde_json::from_value(value[0].get("content_key").unwrap().clone()).unwrap();
    let content_value: BeaconContentValue =
        serde_json::from_value(value[0].get("content_value").unwrap().clone()).unwrap();

    // Check if the stored content value in bootnode's DB matches the offered
    let response = wait_for_beacon_content(&peertest.bootnode.ipc_client, content_key).await;
    let received_content_value = match response {
        PossibleBeaconContentValue::ContentPresent(c) => c,
        PossibleBeaconContentValue::ContentAbsent => panic!("Expected beacon content to be found"),
    };
    assert_eq!(
        content_value, received_content_value,
        "The received beacon content {received_content_value:?}, must match the expected {content_value:?}",
    );
}
