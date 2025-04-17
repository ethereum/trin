use std::{path::PathBuf, str::FromStr};

use alloy::primitives::B256;
use ethportal_api::{
    jsonrpsee::http_client::HttpClient, types::network::Subnetwork, BeaconContentKey,
    BeaconContentValue, ContentValue, RawContentValue,
};
use portal_bridge::{
    api::consensus::ConsensusApi,
    bridge::beacon::BeaconBridge,
    census::{Census, ENR_OFFER_LIMIT},
    cli::{BridgeConfig, BridgeId, DEFAULT_EXECUTABLE_PATH, DEFAULT_SUBNETWORK},
    constants::{DEFAULT_OFFER_LIMIT, DEFAULT_TOTAL_REQUEST_TIMEOUT},
    types::mode::BridgeMode,
    DEFAULT_BASE_CL_ENDPOINT, DEFAULT_BASE_EL_ENDPOINT, FALLBACK_BASE_CL_ENDPOINT,
    FALLBACK_BASE_EL_ENDPOINT,
};
use portalnet::constants::{DEFAULT_DISCOVERY_PORT, DEFAULT_NETWORK, DEFAULT_WEB3_HTTP_PORT};
use serde::Deserialize;
use serde_json::Value;
use tokio::time::{sleep, Duration};
use trin_utils::cli::network_parser;
use url::Url;

use crate::{utils::wait_for_beacon_content, Peertest};

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

    let bridge_config = BridgeConfig {
        executable_path: PathBuf::from(DEFAULT_EXECUTABLE_PATH),
        mode: BridgeMode::Latest,
        e2hs_range: None,
        e2hs_randomize: false,
        portal_subnetwork: Subnetwork::from_str(DEFAULT_SUBNETWORK)
            .expect("Failed to parse default subnetwork"),
        network: network_parser(DEFAULT_NETWORK).expect("Failed to parse default network"),
        metrics_url: None,
        client_metrics_url: None,
        bootnodes: "default".to_owned(),
        external_ip: None,
        private_key: B256::random(),
        el_provider: Url::parse(DEFAULT_BASE_EL_ENDPOINT)
            .expect("Failed to parse default el provider"),
        el_provider_fallback: Url::parse(FALLBACK_BASE_EL_ENDPOINT)
            .expect("Failed to parse default el provider fallback"),
        cl_provider: Url::parse(DEFAULT_BASE_CL_ENDPOINT)
            .expect("Failed to parse default cl provider"),
        cl_provider_fallback: Url::parse(FALLBACK_BASE_CL_ENDPOINT)
            .expect("Failed to parse default cl provider fallback"),
        base_discovery_port: DEFAULT_DISCOVERY_PORT,
        base_rpc_port: DEFAULT_WEB3_HTTP_PORT,
        offer_limit: DEFAULT_OFFER_LIMIT,
        enr_offer_limit: ENR_OFFER_LIMIT,
        filter_clients: Vec::new(),
        request_timeout: DEFAULT_TOTAL_REQUEST_TIMEOUT,
        bridge_id: BridgeId { id: 1, total: 1 },
        data_dir: None,
    };

    let mut census = Census::new(portal_client.clone(), &bridge_config);
    let census_handle = census.init([Subnetwork::Beacon]).await.unwrap();
    let bridge = BeaconBridge::new(consensus_api, mode, portal_client.clone(), census);
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
    census_handle.abort();
    drop(census_handle);
}
