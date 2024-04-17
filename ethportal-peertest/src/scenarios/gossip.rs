use std::net::{IpAddr, Ipv4Addr};

use tracing::info;

use crate::{
    utils::{fixture_header_with_proof, wait_for_history_content},
    Peertest,
};
use ethportal_api::{
    jsonrpsee::async_client::Client, types::cli::TrinConfig, Discv5ApiClient,
    HistoryNetworkApiClient,
};

pub async fn test_gossip_with_trace(peertest: &Peertest, target: &Client) {
    info!("Testing Gossip with tracing");

    let _ = target.ping(peertest.bootnode.enr.clone()).await.unwrap();
    let (content_key, content_value) = fixture_header_with_proof();
    let result = target
        .trace_gossip(content_key.clone(), content_value.clone())
        .await
        .unwrap();

    assert_eq!(result.offered.len(), 1);
    assert_eq!(result.accepted.len(), 1);
    assert_eq!(result.transferred.len(), 1);

    // Check if the stored content value in bootnode's DB matches the offered
    let received_content_value =
        wait_for_history_content(&peertest.bootnode.ipc_client, content_key.clone()).await;
    assert_eq!(
        content_value, received_content_value,
        "The received content {received_content_value:?}, must match the expected {content_value:?}",
    );

    // Spin up a fresh client, not connected to existing peertest
    let test_ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    // Use an uncommon port for the peertest to avoid clashes.
    let test_discovery_port = 8899;
    let external_addr = format!("{test_ip_addr}:{test_discovery_port}");
    let fresh_ipc_path = format!("/tmp/trin-jsonrpc-{test_discovery_port}.ipc");
    let trin_config = TrinConfig::new_from(
        [
            "trin",
            "--portal-subnetworks",
            "history,state",
            "--external-address",
            external_addr.as_str(),
            "--web3-ipc-path",
            fresh_ipc_path.as_str(),
            "--ephemeral",
            "--discovery-port",
            test_discovery_port.to_string().as_ref(),
            "--bootnodes",
            "none",
        ]
        .iter(),
    )
    .unwrap();

    let _test_client_rpc_handle = trin::run_trin(trin_config).await.unwrap();
    let fresh_target = reth_ipc::client::IpcClientBuilder::default()
        .build(fresh_ipc_path)
        .await
        .unwrap();
    let fresh_enr = fresh_target.node_info().await.unwrap().enr;

    // connect to new node
    let _ = target.ping(fresh_enr).await.unwrap();

    // send new trace gossip request
    let result = target
        .trace_gossip(content_key.clone(), content_value.clone())
        .await
        .unwrap();

    assert_eq!(result.offered.len(), 2);
    assert_eq!(result.accepted.len(), 1);
    assert_eq!(result.transferred.len(), 1);

    // Check if the stored content value in fresh node's DB matches the offered
    let received_content_value = wait_for_history_content(&fresh_target, content_key.clone()).await;
    assert_eq!(
        content_value, received_content_value,
        "The received content {received_content_value:?}, must match the expected {content_value:?}",
    );

    // test trace gossip without any expected accepts
    let result = target
        .trace_gossip(content_key, content_value)
        .await
        .unwrap();

    assert_eq!(result.offered.len(), 2);
    assert_eq!(result.accepted.len(), 0);
    assert_eq!(result.transferred.len(), 0);
}
