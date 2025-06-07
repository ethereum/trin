use ethportal_api::{jsonrpsee::async_client::Client, HistoryNetworkApiClient};
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
