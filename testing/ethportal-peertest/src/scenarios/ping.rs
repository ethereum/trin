use ethportal_api::{
    types::{
        distance::Distance,
        network::Subnetwork,
        ping_extensions::{
            decode::PingExtension,
            extension_types::PingExtensionType,
            extensions::{
                type_0::ClientInfoRadiusCapabilities, type_1::BasicRadius, type_2::HistoryRadius,
            },
        },
    },
    BeaconNetworkApiClient, HistoryNetworkApiClient, StateNetworkApiClient,
};
use jsonrpsee::async_client::Client;
use tracing::info;
use ureq::json;

use crate::{Peertest, PeertestNode};

pub async fn test_ping_no_specified_ping_payload(
    subnetwork: Subnetwork,
    target: &Client,
    peertest: &Peertest,
) {
    info!("Testing ping for {subnetwork}");
    let bootnode_enr = peertest.bootnode.enr.clone();
    let bootnode_sequence = bootnode_enr.seq();
    let result = match subnetwork {
        Subnetwork::Beacon => BeaconNetworkApiClient::ping(target, bootnode_enr, None, None),
        Subnetwork::History => HistoryNetworkApiClient::ping(target, bootnode_enr, None, None),
        Subnetwork::State => StateNetworkApiClient::ping(target, bootnode_enr, None, None),
        _ => panic!("Unexpected subnetwork: {subnetwork}"),
    }
    .await
    .unwrap_or_else(|_| panic!("Ping failed {subnetwork}"));

    let radius = match PingExtension::decode_json(
        PingExtensionType::try_from(result.payload_type)
            .unwrap_or_else(|err| panic!("Failed to convert payload type {err:?}")),
        result.payload,
    ) {
        Ok(PingExtension::Capabilities(payload)) => payload.data_radius,
        _ => panic!("Unexpected ping extension"),
    };

    assert_eq!(radius, Distance::MAX);
    assert_eq!(result.enr_seq, bootnode_sequence);
}

pub async fn test_ping_capabilities_payload(target: &Client, peertest: &Peertest) {
    info!("Testing ping with capabilities payload");
    let bootnode_enr = peertest.bootnode.enr.clone();
    let bootnode_sequence = bootnode_enr.seq();
    let result = HistoryNetworkApiClient::ping(
        target,
        bootnode_enr,
        Some(0),
        Some(json!(ClientInfoRadiusCapabilities::new(
            Distance::MAX,
            vec![0, 2]
        ))),
    )
    .await
    .unwrap_or_else(|_| panic!("Ping failed"));

    let client_info_radius_capabilities = match PingExtension::decode_json(
        PingExtensionType::try_from(result.payload_type)
            .unwrap_or_else(|err| panic!("Failed to convert payload type {err:?}")),
        result.payload,
    ) {
        Ok(PingExtension::Capabilities(payload)) => payload,
        _ => panic!("Unexpected ping extension"),
    };

    assert_eq!(client_info_radius_capabilities.data_radius, Distance::MAX);
    assert_eq!(
        client_info_radius_capabilities.capabilities().unwrap(),
        vec![
            PingExtensionType::Capabilities,
            PingExtensionType::HistoryRadius,
            PingExtensionType::Error
        ]
    );
    assert_eq!(result.enr_seq, bootnode_sequence);
}

pub async fn test_ping_basic_radius_payload(target: &Client, peertest: &Peertest) {
    info!("Testing ping with basic radius payload");
    let bootnode_enr = peertest.bootnode.enr.clone();
    let bootnode_sequence = bootnode_enr.seq();
    let result = StateNetworkApiClient::ping(
        target,
        bootnode_enr,
        Some(1),
        Some(json!(BasicRadius::new(Distance::MAX))),
    )
    .await
    .unwrap_or_else(|_| panic!("Ping failed"));

    let basic_radius = match PingExtension::decode_json(
        PingExtensionType::try_from(result.payload_type)
            .unwrap_or_else(|err| panic!("Failed to convert payload type {err:?}")),
        result.payload.clone(),
    ) {
        Ok(PingExtension::BasicRadius(payload)) => payload,
        _ => panic!(
            "Unexpected ping extension {:?} {:?}",
            result.payload_type, result.payload
        ),
    };

    assert_eq!(basic_radius.data_radius, Distance::MAX);
    assert_eq!(result.enr_seq, bootnode_sequence);
}

pub async fn test_ping_history_radius_payload(target: &Client, peertest: &Peertest) {
    info!("Testing ping with history radius payload");
    let bootnode_enr = peertest.bootnode.enr.clone();
    let bootnode_sequence = bootnode_enr.seq();
    let result = HistoryNetworkApiClient::ping(
        target,
        bootnode_enr,
        Some(2),
        Some(json!(HistoryRadius::new(Distance::MAX, 0))),
    )
    .await
    .unwrap_or_else(|_| panic!("Ping failed"));

    let history_radius = match PingExtension::decode_json(
        PingExtensionType::try_from(result.payload_type)
            .unwrap_or_else(|err| panic!("Failed to convert payload type {err:?}")),
        result.payload,
    ) {
        Ok(PingExtension::HistoryRadius(payload)) => payload,
        _ => panic!("Unexpected ping extension"),
    };

    assert_eq!(history_radius.data_radius, Distance::MAX);
    assert_eq!(history_radius.ephemeral_header_count, 0);
    assert_eq!(result.enr_seq, bootnode_sequence);
}

pub async fn test_ping_invalid_payload_type_client(target: &Client, peertest: &Peertest) {
    info!("Testing ping with invalid payload type");
    let bootnode_enr = peertest.bootnode.enr.clone();
    let error = StateNetworkApiClient::ping(
        target,
        bootnode_enr,
        Some(4444),
        Some(json!(BasicRadius::new(Distance::MAX))),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("Payload type not supported"));
    assert!(error.contains("client"));
    assert!(error.contains("-39004"));
}

pub async fn test_ping_invalid_payload_type_subnetwork(target: &Client, peertest: &Peertest) {
    info!("Testing ping with invalid payload type");
    let bootnode_enr = peertest.bootnode.enr.clone();
    let error = StateNetworkApiClient::ping(
        target,
        bootnode_enr,
        Some(2),
        Some(json!(BasicRadius::new(Distance::MAX))),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("Payload type not supported"));
    assert!(error.contains("subnetwork"));
    assert!(error.contains("-39004"));
}

pub async fn test_ping_failed_to_decode_payload(target: &Client, peertest: &Peertest) {
    info!("Testing ping with invalid payload");
    let bootnode_enr = peertest.bootnode.enr.clone();
    let error = StateNetworkApiClient::ping(target, bootnode_enr, Some(0), Some(json!({})))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("Failed to decode payload"));
    assert!(error.contains("-39005"));
}

pub async fn test_ping_cross_network(mainnet_target: &Client, angelfood_node: &PeertestNode) {
    info!("Testing ping for history cross mainnet and angelfood discv5 protocol id");
    let angelfood_enr = angelfood_node.enr.clone();
    if let Ok(pong) = HistoryNetworkApiClient::ping(mainnet_target, angelfood_enr, None, None).await
    {
        panic!("Expected ping to fail as mainnet/angelfood history nodes shouldn't be able to communicate {pong:?}");
    };
}
