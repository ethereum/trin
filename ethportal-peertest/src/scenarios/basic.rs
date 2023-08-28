use crate::constants::fixture_header_with_proof;
use crate::Peertest;
use ethereum_types::{H256, U256};
use ethportal_api::types::distance::Distance;
use ethportal_api::{
    BlockHeaderKey, Discv5ApiClient, HistoryContentKey, HistoryNetworkApiClient,
    PossibleHistoryContentValue, Web3ApiClient,
};
use jsonrpsee::async_client::Client;
use ssz::Encode;
use tracing::info;
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
    assert!(result.local_node_id.starts_with("0x"));
}

pub async fn test_history_radius(target: &Client) {
    info!("Testing portal_historyRadius");
    let result = target.radius().await.unwrap();
    assert_eq!(
        result,
        U256::from_big_endian(Distance::MAX.as_ssz_bytes().as_slice())
    );
}

pub async fn test_history_add_enr(target: &Client, peertest: &Peertest) {
    info!("Testing portal_historyAddEnr");
    let result = HistoryNetworkApiClient::add_enr(target, peertest.bootnode.enr.clone())
        .await
        .unwrap();
    assert!(result);
}

pub async fn test_history_get_enr(target: &Client, peertest: &Peertest) {
    info!("Testing portal_historyGetEnr");
    let result = HistoryNetworkApiClient::get_enr(target, peertest.bootnode.enr.node_id())
        .await
        .unwrap();
    assert_eq!(result, peertest.bootnode.enr);
}

pub async fn test_history_delete_enr(target: &Client, peertest: &Peertest) {
    info!("Testing portal_historyDeleteEnr");
    let result = HistoryNetworkApiClient::delete_enr(target, peertest.bootnode.enr.node_id())
        .await
        .unwrap();
    assert!(result);
}

pub async fn test_history_lookup_enr(peertest: &Peertest) {
    info!("Testing portal_historyLookupEnr");
    let result = HistoryNetworkApiClient::lookup_enr(
        &peertest.bootnode.ipc_client,
        peertest.nodes[0].enr.node_id(),
    )
    .await
    .unwrap();
    assert_eq!(result, peertest.nodes[0].enr);
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
    assert!(result.contains(&peertest.nodes[0].enr));
}

pub async fn test_history_find_nodes_zero_distance(target: &Client, peertest: &Peertest) {
    info!("Testing portal_historyFindNodes with zero distance");
    let result = target
        .find_nodes(peertest.bootnode.enr.clone(), vec![0])
        .await
        .unwrap();
    assert!(result.contains(&peertest.bootnode.enr));
}

pub async fn test_history_store(target: &Client) {
    info!("Testing portal_historyStore");
    let (content_key, content_value) = fixture_header_with_proof();
    let result = target.store(content_key, content_value).await.unwrap();
    assert!(result);
}

pub async fn test_history_routing_table_info(target: &Client) {
    info!("Testing portal_historyRoutingTableInfo");
    let result = HistoryNetworkApiClient::routing_table_info(target).await;
    assert!(result.is_ok());
}

pub async fn test_history_local_content_absent(target: &Client) {
    info!("Testing portal_historyLocalContent absent");
    let content_key = HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey {
        block_hash: H256::random().into(),
    });
    let result = target.local_content(content_key).await.unwrap();

    if let PossibleHistoryContentValue::ContentPresent(_) = result {
        panic!("Expected absent content");
    };
}
