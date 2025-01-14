use ethportal_api::{
    jsonrpsee::http_client::HttpClient, BeaconContentKey, BeaconContentValue, ContentValue,
    RawContentValue,
};
use portal_bridge::{
    api::{consensus::ConsensusApi, execution::ExecutionApi},
    bridge::{beacon::BeaconBridge, history::HistoryBridge},
    constants::{DEFAULT_GOSSIP_LIMIT, DEFAULT_TOTAL_REQUEST_TIMEOUT},
    types::mode::BridgeMode,
};
use serde::Deserialize;
use serde_json::Value;
use tokio::time::{sleep, Duration};
use trin_validation::oracle::HeaderOracle;
use url::Url;

use crate::{
    utils::{fixture_header_by_hash_1000010, wait_for_beacon_content, wait_for_history_content},
    Peertest,
};

pub async fn test_history_bridge(peertest: &Peertest, portal_client: &HttpClient) {
    let header_oracle = HeaderOracle::default();
    let epoch_acc_path = "validation_assets/epoch_acc.bin".into();
    let mode = BridgeMode::Test("./../../test_assets/portalnet/bridge_data.json".into());
    // url doesn't matter, we're not making any requests
    let client_url = Url::parse("http://www.null.com").unwrap();
    let execution_api = ExecutionApi::new(
        client_url.clone(),
        client_url,
        DEFAULT_TOTAL_REQUEST_TIMEOUT,
    )
    .await
    .unwrap();
    // Wait for bootnode to start
    sleep(Duration::from_secs(1)).await;
    let bridge = HistoryBridge::new(
        mode,
        execution_api,
        portal_client.clone(),
        header_oracle,
        epoch_acc_path,
        DEFAULT_GOSSIP_LIMIT,
    );
    bridge.launch().await;
    let (content_key, content_value) = fixture_header_by_hash_1000010();
    // Check if the stored content value in bootnode's DB matches the offered
    let received_content_value =
        wait_for_history_content(&peertest.bootnode.ipc_client, content_key).await;
    assert_eq!(
        content_value, received_content_value,
        "The received content {received_content_value:?}, must match the expected {content_value:?}",
    );
}

pub async fn test_beacon_bridge(peertest: &Peertest, portal_client: &HttpClient) {
    let mode = BridgeMode::Test("./../../test_assets/portalnet/beacon_bridge_data.yaml".into());
    // Wait for bootnode to start
    sleep(Duration::from_secs(1)).await;
    // url doesn't matter, we're not making any requests
    let client_url = Url::parse("http://www.null.com").unwrap();
    let consensus_api = ConsensusApi::new(
        client_url.clone(),
        client_url,
        DEFAULT_TOTAL_REQUEST_TIMEOUT,
    )
    .await
    .unwrap();
    let bridge = BeaconBridge::new(consensus_api, mode, portal_client.clone());
    bridge.launch().await;

    let value = std::fs::read_to_string("./../../test_assets/portalnet/beacon_bridge_data.yaml")
        .expect("cannot find test asset");
    let value: Value = serde_yaml::from_str(&value).unwrap();
    let content_key = BeaconContentKey::deserialize(&value[0]["content_key"]).unwrap();
    let content_value = RawContentValue::deserialize(&value[0]["content_value"]).unwrap();
    let content_value = BeaconContentValue::decode(&content_key, &content_value).unwrap();

    // Check if the stored content value in bootnode's DB matches the offered
    let received_content_value =
        wait_for_beacon_content(&peertest.bootnode.ipc_client, content_key).await;
    assert_eq!(
        content_value, received_content_value,
        "The received beacon content {received_content_value:?}, must match the expected {content_value:?}",
    );
}
