use ethportal_api::HistoryNetworkApiClient;

use crate::Peertest;

/// Minimal bridge test: checks that the bootnode can ping the first node.
pub async fn test_bridge_ping(peertest: &Peertest) -> Result<(), String> {
    if peertest.nodes.is_empty() {
        return Err("No nodes in peertest".to_string());
    }
    let target_node = &peertest.nodes[0];
    let result = HistoryNetworkApiClient::ping(
        &peertest.bootnode.ipc_client,
        target_node.enr.clone(),
        None,
        None,
    )
    .await;
    result.map_err(|e| format!("Ping failed: {e:?}"))?;
    Ok(())
}

/// Test bridge routing table functionality
pub async fn test_bridge_routing_table(peertest: &Peertest) -> Result<(), String> {
    // Total nodes = bootnode + additional nodes
    let total_nodes = 1 + peertest.nodes.len();
    if total_nodes < 2 {
        return Err("Need at least 2 nodes for routing table test".to_string());
    }

    // Test routing table lookup from bootnode
    let routing_table_info =
        HistoryNetworkApiClient::routing_table_info(&peertest.bootnode.ipc_client)
            .await
            .map_err(|e| format!("Failed to get routing table info: {e:?}"))?;

    // Verify we have some routing table entries
    if routing_table_info.buckets.buckets.is_empty() {
        return Err("Routing table should have some entries".to_string());
    }

    // Test ENR lookup for the first additional node
    if !peertest.nodes.is_empty() {
        let target_node = &peertest.nodes[0];
        let enr_result = HistoryNetworkApiClient::get_enr(
            &peertest.bootnode.ipc_client,
            target_node.enr.node_id(),
        )
        .await
        .map_err(|e| format!("Failed to get ENR: {e:?}"))?;

        if enr_result != target_node.enr {
            return Err("ENR lookup returned unexpected ENR".to_string());
        }
    }

    Ok(())
}
