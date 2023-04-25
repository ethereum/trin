use crate::constants::{HISTORY_CONTENT_KEY, HISTORY_CONTENT_VALUE};
use crate::Peertest;
use ethereum_types::U256;
use ethportal_api::{Discv5ApiClient, HistoryNetworkApiClient, Web3ApiClient};
use jsonrpsee::async_client::Client;
use serde_json::json;
use ssz::Encode;
use tracing::info;
use trin_types::content_key::HistoryContentKey;
use trin_types::content_value::{HistoryContentValue, PossibleHistoryContentValue};
use trin_types::distance::Distance;
use trin_utils::version::get_trin_version;

pub async fn test_web3_client_version(target: &Client) {
    info!("Testing web3_clientVersion");
    let result = target.client_version().await.unwrap();
    let expected_version = format!("trin v{}", get_trin_version());
    assert_eq!(result, expected_version);
}

pub async fn test_discv5_node_info(peertest: &Peertest) {
    info!("Testing discv5_nodeInfo");
    let result = peertest.bootnode.ipc_client.node_info().await.unwrap();
    assert_eq!(result.enr, peertest.bootnode.enr);
}

pub async fn test_discv5_routing_table_info(target: &Client) {
    info!("Testing discv5_routingTableInfo");
    let result = Discv5ApiClient::routing_table_info(target).await.unwrap();
    let local_key = result.get("localNodeId").unwrap();
    assert!(local_key.is_string());
    assert!(local_key.as_str().unwrap().starts_with("0x"));
    assert!(result.get("buckets").unwrap().is_array());
}

pub async fn test_history_radius(target: &Client) {
    info!("Testing portal_historyRadius");
    let result = target.radius().await.unwrap();
    assert_eq!(
        result,
        U256::from_big_endian(Distance::MAX.as_ssz_bytes().as_slice())
    );
}

pub async fn test_history_ping(target: &Client, peertest: &Peertest) {
    info!("Testing portal_historyPing");
    let result = target.ping(peertest.bootnode.enr.clone()).await.unwrap();
    assert_eq!(
        result.data_radius,
        U256::from_big_endian(Distance::MAX.as_ssz_bytes().as_slice())
    );
    assert_eq!(result.enr_seq, 1);
}

pub async fn test_history_find_nodes(target: &Client, peertest: &Peertest) {
    info!("Testing portal_historyFindNodes");
    let result = target
        .find_nodes(peertest.bootnode.enr.clone(), vec![256])
        .await
        .unwrap();
    assert_eq!(result.total, 1);
    assert!(result.enrs.contains(&peertest.nodes[0].enr));
}

pub async fn test_history_find_nodes_zero_distance(target: &Client, peertest: &Peertest) {
    info!("Testing portal_historyFindNodes with zero distance");
    let result = target
        .find_nodes(peertest.bootnode.enr.clone(), vec![0])
        .await
        .unwrap();
    assert_eq!(result.total, 1);
    assert!(result.enrs.contains(&peertest.bootnode.enr));
}

pub async fn test_history_store(target: &Client) {
    info!("Testing portal_historyStore");

    let content_key: HistoryContentKey =
        serde_json::from_value(json!(HISTORY_CONTENT_KEY)).unwrap();
    let content_value: HistoryContentValue =
        serde_json::from_value(json!(HISTORY_CONTENT_VALUE)).unwrap();

    let result = target.store(content_key, content_value).await.unwrap();
    assert!(result);
}

pub async fn test_history_routing_table_info(target: &Client) {
    info!("Testing portal_historyRoutingTableInfo");
    let result = HistoryNetworkApiClient::routing_table_info(target)
        .await
        .unwrap();
    assert!(result.get("buckets").unwrap().is_object());
    assert!(result.get("numBuckets").unwrap().is_u64());
    assert!(result.get("numNodes").unwrap().is_u64());
    assert!(result.get("numConnected").unwrap().is_u64());
}

pub async fn test_history_local_content_absent(target: &Client) {
    info!("Testing portal_historyLocalContent absent");

    let content_key: HistoryContentKey = serde_json::from_value(json!(
        "0x00cb5cab7266694daa0d28cbf40496c08dd30bf732c41e0455e7ad389c10d79f4f"
    ))
    .unwrap();
    let result = target.local_content(content_key).await.unwrap();

    if let PossibleHistoryContentValue::ContentPresent(_) = result {
        panic!("Expected absent content");
    };
}
