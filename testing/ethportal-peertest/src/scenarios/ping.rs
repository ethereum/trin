use ethportal_api::{
    types::{
        distance::Distance,
        network::Subnetwork,
        ping_extensions::{
            decode::PingExtension,
            extension_types::PingExtensionType,
            extensions::{
                type_0::{ClientInfo, ClientInfoRadiusCapabilities},
                type_1::BasicRadius,
                type_2::HistoryRadius,
            },
        },
    },
    BeaconNetworkApiClient, LegacyHistoryNetworkApiClient, StateNetworkApiClient,
};
use jsonrpsee::async_client::Client;
use serde_json::json;
use tracing::info;

use crate::Peertest;

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
        Subnetwork::LegacyHistory => {
            LegacyHistoryNetworkApiClient::ping(target, bootnode_enr, None, None)
        }
        Subnetwork::State => StateNetworkApiClient::ping(target, bootnode_enr, None, None),
        _ => panic!("Unexpected subnetwork: {subnetwork}"),
    }
    .await
    .unwrap_or_else(|err| panic!("Ping should succeed. Subnetwork: {subnetwork}, {err:?}"));

    let radius = match PingExtension::decode_json(result.payload_type, result.payload) {
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
    let result = LegacyHistoryNetworkApiClient::ping(
        target,
        bootnode_enr,
        Some(PingExtensionType::Capabilities),
        Some(json!(ClientInfoRadiusCapabilities::new(
            Distance::MAX,
            vec![
                PingExtensionType::Capabilities,
                PingExtensionType::HistoryRadius
            ]
        ))),
    )
    .await
    .expect("Ping should succeed");

    let client_info_radius_capabilities =
        match PingExtension::decode_json(result.payload_type, result.payload) {
            Ok(PingExtension::Capabilities(payload)) => payload,
            _ => panic!("Unexpected ping extension"),
        };

    assert_eq!(client_info_radius_capabilities.data_radius, Distance::MAX);
    assert_eq!(
        client_info_radius_capabilities.capabilities.to_vec(),
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
        Some(PingExtensionType::BasicRadius),
        Some(json!(BasicRadius::new(Distance::MAX))),
    )
    .await
    .expect("Ping should succeed");

    let basic_radius = match PingExtension::decode_json(result.payload_type, result.payload.clone())
    {
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
    let result = LegacyHistoryNetworkApiClient::ping(
        target,
        bootnode_enr,
        Some(PingExtensionType::HistoryRadius),
        Some(json!(HistoryRadius::new(Distance::MAX, 0))),
    )
    .await
    .expect("Ping should succeed");

    let history_radius = match PingExtension::decode_json(result.payload_type, result.payload) {
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
        Some(PingExtensionType::NonSupportedExtension(4444)),
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
        Some(PingExtensionType::HistoryRadius),
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
    let error = StateNetworkApiClient::ping(
        target,
        bootnode_enr,
        Some(PingExtensionType::Capabilities),
        Some(json!({})),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("Failed to decode payload"));
    assert!(error.contains("-39005"));
}

pub async fn test_ping_capabilities_payload_type(target: &Client, peertest: &Peertest) {
    info!("Testing ping with capabilities payload type");
    let bootnode_enr = peertest.bootnode.enr.clone();
    let bootnode_sequence = bootnode_enr.seq();
    let result = StateNetworkApiClient::ping(
        target,
        bootnode_enr,
        Some(PingExtensionType::Capabilities),
        None,
    )
    .await
    .expect("Ping should succeed");

    let capabilities_payload =
        match PingExtension::decode_json(result.payload_type, result.payload.clone()) {
            Ok(PingExtension::Capabilities(payload)) => payload,
            _ => panic!(
                "Unexpected ping extension {:?} {:?}",
                result.payload_type, result.payload
            ),
        };

    assert_eq!(capabilities_payload.data_radius, Distance::MAX);
    assert_eq!(
        capabilities_payload.get_client_info(),
        ClientInfo::trin_client_info(),
    );
    assert_eq!(capabilities_payload.capabilities.len(), 3);
    assert_eq!(result.enr_seq, bootnode_sequence);
}

pub async fn test_ping_basic_radius_payload_type(target: &Client, peertest: &Peertest) {
    info!("Testing ping with basic radius payload type");
    let bootnode_enr = peertest.bootnode.enr.clone();
    let bootnode_sequence = bootnode_enr.seq();
    let result = StateNetworkApiClient::ping(
        target,
        bootnode_enr,
        Some(PingExtensionType::BasicRadius),
        None,
    )
    .await
    .expect("Ping should succeed");

    let basic_radius = match PingExtension::decode_json(result.payload_type, result.payload.clone())
    {
        Ok(PingExtension::BasicRadius(payload)) => payload,
        _ => panic!(
            "Unexpected ping extension {:?} {:?}",
            result.payload_type, result.payload
        ),
    };

    assert_eq!(basic_radius.data_radius, Distance::MAX);
    assert_eq!(result.enr_seq, bootnode_sequence);
}

pub async fn test_ping_history_radius_payload_type(target: &Client, peertest: &Peertest) {
    info!("Testing ping with history radius payload type");
    let bootnode_enr = peertest.bootnode.enr.clone();
    let bootnode_sequence = bootnode_enr.seq();
    let result = LegacyHistoryNetworkApiClient::ping(
        target,
        bootnode_enr,
        Some(PingExtensionType::HistoryRadius),
        None,
    )
    .await
    .expect("Ping should succeed");

    let history_radius =
        match PingExtension::decode_json(result.payload_type, result.payload.clone()) {
            Ok(PingExtension::HistoryRadius(payload)) => payload,
            _ => panic!(
                "Unexpected ping extension {:?} {:?}",
                result.payload_type, result.payload
            ),
        };

    assert_eq!(history_radius.data_radius, Distance::MAX);
    // todo: update this when the default value is changed
    assert_eq!(history_radius.ephemeral_header_count, 0);
    assert_eq!(result.enr_seq, bootnode_sequence);
}
