use std::{
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};

use tokio::time::{sleep, Duration};
use tracing::info;

use crate::{
    utils::{fixture_header_with_proof, wait_for_history_content},
    Peertest,
};
use ethportal_api::{
    jsonrpsee::async_client::Client,
    types::{cli::TrinConfig, enr::Enr},
    utils::bytes::hex_encode,
    Discv5ApiClient, HistoryNetworkApiClient,
};

pub async fn test_unpopulated_offer(peertest: &Peertest, target: &Client) {
    info!("Testing Unpopulated OFFER/ACCEPT flow");

    let (content_key, content_value) = fixture_header_with_proof();
    // Store content to offer in the testnode db
    let store_result = target
        .store(content_key.clone(), content_value.clone())
        .await
        .unwrap();

    assert!(store_result);

    // Send unpopulated offer request from testnode to bootnode
    let result = target
        .offer(
            Enr::from_str(&peertest.bootnode.enr.to_base64()).unwrap(),
            content_key.clone(),
            None,
        )
        .await
        .unwrap();

    // Check that ACCEPT response sent by bootnode accepted the offered content
    assert_eq!(hex_encode(result.content_keys.into_bytes()), "0x03");

    // Check if the stored content value in bootnode's DB matches the offered
    let received_content_value =
        wait_for_history_content(&peertest.bootnode.ipc_client, content_key).await;
    assert_eq!(
        content_value, received_content_value,
        "The received content {received_content_value:?}, must match the expected {content_value:?}",
    );
}

pub async fn test_unpopulated_offer_fails_with_missing_content(
    peertest: &Peertest,
    target: &Client,
) {
    info!("Testing Unpopulated OFFER/ACCEPT flow with missing content");

    let (content_key, _content_value) = fixture_header_with_proof();

    // validate that unpopulated offer fails if content not available locally
    match target
        .offer(
            Enr::from_str(&peertest.bootnode.enr.to_base64()).unwrap(),
            content_key.clone(),
            None,
        )
        .await
    {
        Ok(_) => panic!("Unpopulated offer should have failed"),
        Err(e) => {
            assert!(e
                .to_string()
                .contains("Content key not found in local store"));
        }
    }
}

pub async fn test_populated_offer(peertest: &Peertest, target: &Client) {
    info!("Testing Populated Offer/ACCEPT flow");

    let (content_key, content_value) = fixture_header_with_proof();
    let result = target
        .offer(
            Enr::from_str(&peertest.bootnode.enr.to_base64()).unwrap(),
            content_key.clone(),
            Some(content_value.clone()),
        )
        .await
        .unwrap();

    // Check that ACCEPT response sent by bootnode accepted the offered content
    assert_eq!(hex_encode(result.content_keys.into_bytes()), "0x03");

    // Check if the stored content value in bootnode's DB matches the offered
    let received_content_value =
        wait_for_history_content(&peertest.bootnode.ipc_client, content_key).await;
    assert_eq!(
        content_value, received_content_value,
        "The received content {received_content_value:?}, must match the expected {content_value:?}",
    );
}

pub async fn test_offer_propagates_gossip(peertest: &Peertest, target: &Client) {
    info!("Testing populated offer propagates gossip");

    // connect target to network
    let _ = target.ping(peertest.bootnode.enr.clone()).await.unwrap();

    // Spin up a fresh client, not connected to existing peertest
    let test_ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    // Use an uncommon port for the peertest to avoid clashes.
    let test_discovery_port = 8889;
    let external_addr = format!("{test_ip_addr}:{test_discovery_port}");
    let fresh_ipc_path = format!("/tmp/trin-jsonrpc-{test_discovery_port}.ipc");
    let trin_config = TrinConfig::new_from(
        [
            "trin",
            "--portal-subnetworks",
            "history",
            "--external-address",
            external_addr.as_str(),
            "--mb",
            "10",
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

    // connect target to network
    let _ = target.ping(fresh_enr.clone()).await.unwrap();

    let (content_key, content_value) = fixture_header_with_proof();
    // use populated offer which means content will *not* be stored in the target's local db
    target
        .offer(
            fresh_enr.clone(),
            content_key.clone(),
            Some(content_value.clone()),
        )
        .await
        .unwrap();

    // sleep to let gossip propagate
    sleep(Duration::from_secs(1)).await;

    // validate that every node in the network now has a local copy of the header
    assert!(
        HistoryNetworkApiClient::local_content(target, content_key.clone())
            .await
            .is_ok()
    );
    assert!(
        HistoryNetworkApiClient::local_content(&fresh_target, content_key.clone())
            .await
            .is_ok()
    );
    assert!(HistoryNetworkApiClient::local_content(
        &peertest.nodes[0].ipc_client,
        content_key.clone()
    )
    .await
    .is_ok());
    assert!(HistoryNetworkApiClient::local_content(
        &peertest.bootnode.ipc_client,
        content_key.clone()
    )
    .await
    .is_ok());
}
