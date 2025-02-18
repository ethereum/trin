use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use alloy::primitives::{B256, U256};
use ethportal_api::{
    types::{distance::Distance, network::Subnetwork},
    version::get_trin_version,
    BeaconNetworkApiClient, ContentValue, Discv5ApiClient, HistoryContentKey,
    HistoryNetworkApiClient, StateNetworkApiClient, Web3ApiClient,
};
use jsonrpsee::async_client::Client;
use ssz::Encode;
use tracing::info;

use crate::{utils::fixture_header_by_hash, Peertest, PeertestNode};

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
    let node_info = target.node_info().await.unwrap();
    let result = Discv5ApiClient::routing_table_info(target).await.unwrap();
    assert_eq!(result.local_node_id, node_info.node_id);
}

pub async fn test_discv5_add_enr(target: &Client, peertest: &Peertest) {
    info!("Testing discv5_addEnr");
    let result = Discv5ApiClient::add_enr(target, peertest.bootnode.enr.clone())
        .await
        .unwrap();
    assert!(result);
}

pub async fn test_discv5_get_enr(target: &Client, peertest: &Peertest) {
    info!("Testing discv5_getEnr");
    let result = Discv5ApiClient::add_enr(target, peertest.bootnode.enr.clone())
        .await
        .unwrap();
    assert!(result);
    let result = Discv5ApiClient::get_enr(target, peertest.bootnode.enr.node_id())
        .await
        .unwrap();
    assert_eq!(result, peertest.bootnode.enr);
}

pub async fn test_discv5_delete_enr(target: &Client, peertest: &Peertest) {
    info!("Testing discv5_deleteEnr");
    let result = Discv5ApiClient::delete_enr(target, peertest.bootnode.enr.node_id())
        .await
        .unwrap();
    assert!(result);
    let result = Discv5ApiClient::get_enr(target, peertest.bootnode.enr.node_id())
        .await
        .unwrap_err();
    assert_eq!(
        result.to_string(),
        "ErrorObject { code: ServerError(-32099), message: \"ENR not found\", data: None }"
    );
    // add it back since scenario tests share resources so a different test could still need it
    let result = Discv5ApiClient::add_enr(target, peertest.bootnode.enr.clone())
        .await
        .unwrap();
    assert!(result);
}

pub async fn test_discv5_update_node_info(target: &Client) {
    info!("Testing discv5_updateNodeInfo");

    let _ = Discv5ApiClient::update_node_info(
        target,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080).to_string(),
        false,
    )
    .await
    .unwrap();

    let node_info = Discv5ApiClient::node_info(target).await.unwrap();
    assert_eq!(node_info.enr.udp4().unwrap(), 8080);

    // switch it back
    let _ = Discv5ApiClient::update_node_info(
        target,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8999).to_string(),
        false,
    )
    .await
    .unwrap();

    let node_info = Discv5ApiClient::node_info(target).await.unwrap();
    assert_eq!(node_info.enr.udp4().unwrap(), 8999);
}

pub async fn test_routing_table_info(subnetwork: Subnetwork, target: &Client) {
    info!("Testing routing_table_info for {subnetwork}");
    let node_info = target.node_info().await.unwrap();
    let result = match subnetwork {
        Subnetwork::Beacon => BeaconNetworkApiClient::routing_table_info(target),
        Subnetwork::History => HistoryNetworkApiClient::routing_table_info(target),
        Subnetwork::State => StateNetworkApiClient::routing_table_info(target),
        _ => panic!("Unexpected subnetwork: {subnetwork}"),
    }
    .await
    .unwrap();
    assert_eq!(result.local_node_id, node_info.node_id);
}

pub async fn test_radius(subnetwork: Subnetwork, target: &Client) {
    info!("Testing radius for {subnetwork}");
    let result = match subnetwork {
        Subnetwork::Beacon => BeaconNetworkApiClient::radius(target),
        Subnetwork::History => HistoryNetworkApiClient::radius(target),
        Subnetwork::State => StateNetworkApiClient::radius(target),
        _ => panic!("Unexpected subnetwork: {subnetwork}"),
    }
    .await
    .unwrap();
    assert_eq!(
        result,
        U256::from_be_slice(Distance::MAX.as_ssz_bytes().as_slice())
    );
}

pub async fn test_add_enr(subnetwork: Subnetwork, target: &Client, peertest: &Peertest) {
    info!("Testing add_enr for {subnetwork}");
    let bootnode_enr = peertest.bootnode.enr.clone();
    let result = match subnetwork {
        Subnetwork::Beacon => BeaconNetworkApiClient::add_enr(target, bootnode_enr),
        Subnetwork::History => HistoryNetworkApiClient::add_enr(target, bootnode_enr),
        Subnetwork::State => StateNetworkApiClient::add_enr(target, bootnode_enr),
        _ => panic!("Unexpected subnetwork: {subnetwork}"),
    }
    .await
    .unwrap();
    assert!(result);
}

pub async fn test_get_enr(subnetwork: Subnetwork, target: &Client, peertest: &Peertest) {
    info!("Testing get_enr for {subnetwork}");
    let node_id = peertest.bootnode.enr.node_id();
    let result = match subnetwork {
        Subnetwork::Beacon => BeaconNetworkApiClient::get_enr(target, node_id),
        Subnetwork::History => HistoryNetworkApiClient::get_enr(target, node_id),
        Subnetwork::State => StateNetworkApiClient::get_enr(target, node_id),
        _ => panic!("Unexpected subnetwork: {subnetwork}"),
    }
    .await
    .unwrap();
    assert_eq!(result, peertest.bootnode.enr);
}

pub async fn test_delete_enr(subnetwork: Subnetwork, target: &Client, peertest: &Peertest) {
    info!("Testing delete_enr for {subnetwork}");
    let node_id = peertest.bootnode.enr.node_id();
    let result = match subnetwork {
        Subnetwork::Beacon => BeaconNetworkApiClient::delete_enr(target, node_id),
        Subnetwork::History => HistoryNetworkApiClient::delete_enr(target, node_id),
        Subnetwork::State => StateNetworkApiClient::delete_enr(target, node_id),
        _ => panic!("Unexpected subnetwork: {subnetwork}"),
    }
    .await
    .unwrap();
    assert!(result);
}

pub async fn test_lookup_enr(subnetwork: Subnetwork, peertest: &Peertest) {
    info!("Testing lookup_enr for {subnetwork}");
    let target = &peertest.bootnode.ipc_client;
    let node_id = peertest.nodes[0].enr.node_id();
    let result = match subnetwork {
        Subnetwork::Beacon => BeaconNetworkApiClient::lookup_enr(target, node_id),
        Subnetwork::History => HistoryNetworkApiClient::lookup_enr(target, node_id),
        Subnetwork::State => StateNetworkApiClient::lookup_enr(target, node_id),
        _ => panic!("Unexpected subnetwork: {subnetwork}"),
    }
    .await
    .unwrap();
    assert_eq!(result, peertest.nodes[0].enr);
}

pub async fn test_ping(subnetwork: Subnetwork, target: &Client, peertest: &Peertest) {
    info!("Testing ping for {subnetwork}");
    let bootnode_enr = peertest.bootnode.enr.clone();
    let bootnode_sequence = bootnode_enr.seq();
    let result = match subnetwork {
        Subnetwork::Beacon => BeaconNetworkApiClient::ping(target, bootnode_enr),
        Subnetwork::History => HistoryNetworkApiClient::ping(target, bootnode_enr),
        Subnetwork::State => StateNetworkApiClient::ping(target, bootnode_enr),
        _ => panic!("Unexpected subnetwork: {subnetwork}"),
    }
    .await
    .unwrap_or_else(|_| panic!("Ping failed {subnetwork}"));
    assert_eq!(
        result.data_radius,
        U256::from_be_slice(Distance::MAX.as_ssz_bytes().as_slice())
    );
    assert_eq!(result.enr_seq, bootnode_sequence);
}

pub async fn test_ping_cross_network(mainnet_target: &Client, angelfood_node: &PeertestNode) {
    info!("Testing ping for history cross mainnet and angelfood discv5 protocol id");
    let angelfood_enr = angelfood_node.enr.clone();
    if let Ok(pong) = HistoryNetworkApiClient::ping(mainnet_target, angelfood_enr).await {
        panic!("Expected ping to fail as mainnet/angelfood history nodes shouldn't be able to communicate {pong:?}");
    };
}

pub async fn test_find_nodes(subnetwork: Subnetwork, target: &Client, peertest: &Peertest) {
    info!("Testing find_nodes for {subnetwork}");
    let bootnode_enr = peertest.bootnode.enr.clone();
    let result = match subnetwork {
        Subnetwork::Beacon => BeaconNetworkApiClient::find_nodes(target, bootnode_enr, vec![256]),
        Subnetwork::History => HistoryNetworkApiClient::find_nodes(target, bootnode_enr, vec![256]),
        Subnetwork::State => StateNetworkApiClient::find_nodes(target, bootnode_enr, vec![256]),
        _ => panic!("Unexpected subnetwork: {subnetwork}"),
    }
    .await
    .unwrap();
    assert!(result.contains(&peertest.nodes[0].enr));
}

pub async fn test_find_nodes_zero_distance(
    subnetwork: Subnetwork,
    target: &Client,
    peertest: &Peertest,
) {
    info!("Testing find_nodes with zero distance for {subnetwork}");
    let bootnode_enr = peertest.bootnode.enr.clone();
    let result = match subnetwork {
        Subnetwork::Beacon => BeaconNetworkApiClient::find_nodes(target, bootnode_enr, vec![0]),
        Subnetwork::History => HistoryNetworkApiClient::find_nodes(target, bootnode_enr, vec![0]),
        Subnetwork::State => StateNetworkApiClient::find_nodes(target, bootnode_enr, vec![0]),
        _ => panic!("Unexpected subnetwork: {subnetwork}"),
    }
    .await
    .unwrap();
    assert!(result.contains(&peertest.bootnode.enr));
}

pub async fn test_history_store(target: &Client) {
    info!("Testing portal_historyStore");
    let (content_key, content_value) = fixture_header_by_hash();
    let result = HistoryNetworkApiClient::store(target, content_key, content_value.encode())
        .await
        .unwrap();
    assert!(result);
}

pub async fn test_history_local_content_absent(target: &Client) {
    info!("Testing portal_historyLocalContent absent");
    let content_key = HistoryContentKey::new_block_header_by_hash(B256::random());
    let error = HistoryNetworkApiClient::local_content(target, content_key)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("Content not found in local storage"));
}
