use crate::{utils::fixture_header_with_proof, Peertest};
use alloy_primitives::{B256, U256};
use ethportal_api::{
    types::{distance::Distance, portal_wire::ProtocolId},
    BeaconNetworkApiClient, BlockHeaderKey, Discv5ApiClient, HistoryContentKey,
    HistoryNetworkApiClient, StateNetworkApiClient, Web3ApiClient,
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

pub async fn test_routing_table_info(protocol: ProtocolId, target: &Client) {
    info!("Testing routing_table_info for {protocol}");
    let result = match protocol {
        ProtocolId::Beacon => BeaconNetworkApiClient::routing_table_info(target),
        ProtocolId::History => HistoryNetworkApiClient::routing_table_info(target),
        ProtocolId::State => StateNetworkApiClient::routing_table_info(target),
        _ => panic!("Unexpected protocol: {protocol}"),
    }
    .await
    .unwrap();
    assert!(result.local_node_id.starts_with("0x"));
}

pub async fn test_radius(protocol: ProtocolId, target: &Client) {
    info!("Testing radius for {protocol}");
    let result = match protocol {
        ProtocolId::Beacon => BeaconNetworkApiClient::radius(target),
        ProtocolId::History => HistoryNetworkApiClient::radius(target),
        ProtocolId::State => StateNetworkApiClient::radius(target),
        _ => panic!("Unexpected protocol: {protocol}"),
    }
    .await
    .unwrap();
    assert_eq!(
        result,
        U256::from_be_slice(Distance::MAX.as_ssz_bytes().as_slice())
    );
}

pub async fn test_add_enr(protocol: ProtocolId, target: &Client, peertest: &Peertest) {
    info!("Testing add_enr for {protocol}");
    let bootnode_enr = peertest.bootnode.enr.clone();
    let result = match protocol {
        ProtocolId::Beacon => BeaconNetworkApiClient::add_enr(target, bootnode_enr),
        ProtocolId::History => HistoryNetworkApiClient::add_enr(target, bootnode_enr),
        ProtocolId::State => StateNetworkApiClient::add_enr(target, bootnode_enr),
        _ => panic!("Unexpected protocol: {protocol}"),
    }
    .await
    .unwrap();
    assert!(result);
}

pub async fn test_get_enr(protocol: ProtocolId, target: &Client, peertest: &Peertest) {
    info!("Testing get_enr for {protocol}");
    let node_id = peertest.bootnode.enr.node_id();
    let result = match protocol {
        ProtocolId::Beacon => BeaconNetworkApiClient::get_enr(target, node_id),
        ProtocolId::History => HistoryNetworkApiClient::get_enr(target, node_id),
        ProtocolId::State => StateNetworkApiClient::get_enr(target, node_id),
        _ => panic!("Unexpected protocol: {protocol}"),
    }
    .await
    .unwrap();
    assert_eq!(result, peertest.bootnode.enr);
}

pub async fn test_delete_enr(protocol: ProtocolId, target: &Client, peertest: &Peertest) {
    info!("Testing delete_enr for {protocol}");
    let node_id = peertest.bootnode.enr.node_id();
    let result = match protocol {
        ProtocolId::Beacon => BeaconNetworkApiClient::delete_enr(target, node_id),
        ProtocolId::History => HistoryNetworkApiClient::delete_enr(target, node_id),
        ProtocolId::State => StateNetworkApiClient::delete_enr(target, node_id),
        _ => panic!("Unexpected protocol: {protocol}"),
    }
    .await
    .unwrap();
    assert!(result);
}

pub async fn test_lookup_enr(protocol: ProtocolId, peertest: &Peertest) {
    info!("Testing lookup_enr for {protocol}");
    let target = &peertest.bootnode.ipc_client;
    let node_id = peertest.nodes[0].enr.node_id();
    let result = match protocol {
        ProtocolId::Beacon => BeaconNetworkApiClient::lookup_enr(target, node_id),
        ProtocolId::History => HistoryNetworkApiClient::lookup_enr(target, node_id),
        ProtocolId::State => StateNetworkApiClient::lookup_enr(target, node_id),
        _ => panic!("Unexpected protocol: {protocol}"),
    }
    .await
    .unwrap();
    assert_eq!(result, peertest.nodes[0].enr);
}

pub async fn test_ping(protocol: ProtocolId, target: &Client, peertest: &Peertest) {
    info!("Testing ping for {protocol}");
    let bootnode_enr = peertest.bootnode.enr.clone();
    let result = match protocol {
        ProtocolId::Beacon => BeaconNetworkApiClient::ping(target, bootnode_enr),
        ProtocolId::History => HistoryNetworkApiClient::ping(target, bootnode_enr),
        ProtocolId::State => StateNetworkApiClient::ping(target, bootnode_enr),
        _ => panic!("Unexpected protocol: {protocol}"),
    }
    .await
    .unwrap();
    assert_eq!(
        result.data_radius,
        U256::from_be_slice(Distance::MAX.as_ssz_bytes().as_slice())
    );
    assert_eq!(result.enr_seq, 1);
}

pub async fn test_ping_cross_network(target: &Client, peertest: &Peertest) {
    info!("Testing ping for history cross mainnet and angelfood discv5 protocol id");
    let bootnode_enr = peertest.bootnode.enr.clone();
    if let Ok(pong) = HistoryNetworkApiClient::ping(target, bootnode_enr).await {
        panic!("Expected ping to fail as mainnet/angelfood history nodes shouldn't be able to communicate {pong:?}");
    };
}

pub async fn test_find_nodes(protocol: ProtocolId, target: &Client, peertest: &Peertest) {
    info!("Testing find_nodes for {protocol}");
    let bootnode_enr = peertest.bootnode.enr.clone();
    let result = match protocol {
        ProtocolId::Beacon => BeaconNetworkApiClient::find_nodes(target, bootnode_enr, vec![256]),
        ProtocolId::History => HistoryNetworkApiClient::find_nodes(target, bootnode_enr, vec![256]),
        ProtocolId::State => StateNetworkApiClient::find_nodes(target, bootnode_enr, vec![256]),
        _ => panic!("Unexpected protocol: {protocol}"),
    }
    .await
    .unwrap();
    assert!(result.contains(&peertest.nodes[0].enr));
}

pub async fn test_find_nodes_zero_distance(
    protocol: ProtocolId,
    target: &Client,
    peertest: &Peertest,
) {
    info!("Testing find_nodes with zero distance for {protocol}");
    let bootnode_enr = peertest.bootnode.enr.clone();
    let result = match protocol {
        ProtocolId::Beacon => BeaconNetworkApiClient::find_nodes(target, bootnode_enr, vec![0]),
        ProtocolId::History => HistoryNetworkApiClient::find_nodes(target, bootnode_enr, vec![0]),
        ProtocolId::State => StateNetworkApiClient::find_nodes(target, bootnode_enr, vec![0]),
        _ => panic!("Unexpected protocol: {protocol}"),
    }
    .await
    .unwrap();
    assert!(result.contains(&peertest.bootnode.enr));
}

pub async fn test_history_store(target: &Client) {
    info!("Testing portal_historyStore");
    let (content_key, content_value) = fixture_header_with_proof();
    let result = HistoryNetworkApiClient::store(target, content_key, content_value)
        .await
        .unwrap();
    assert!(result);
}

pub async fn test_history_local_content_absent(target: &Client) {
    info!("Testing portal_historyLocalContent absent");
    let content_key = HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey {
        block_hash: B256::random().into(),
    });
    let error = HistoryNetworkApiClient::local_content(target, content_key)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("Content not found in local storage"));
}
