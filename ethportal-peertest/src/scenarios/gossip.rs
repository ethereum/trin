use tracing::info;

use crate::{constants::fixture_header_with_proof, utils::wait_for_history_content, Peertest};
use ethportal_api::{HistoryNetworkApiClient, PossibleHistoryContentValue};

pub async fn test_gossip(peertest: &Peertest) {
    info!("Testing gossip flow");

    let (content_key, content_value) = fixture_header_with_proof();
    let result = peertest
        .bootnode
        .ipc_client
        .gossip(content_key.clone(), content_value.clone())
        .await
        .unwrap();

    assert_eq!(result, 1);

    // Check if the stored content value in another node's DB matches the gossiped
    let response = wait_for_history_content(&peertest.nodes[0].ipc_client, content_key).await;
    let received_content_value = match response {
        PossibleHistoryContentValue::ContentPresent(c) => c,
        PossibleHistoryContentValue::ContentAbsent => panic!("Expected content to be found"),
    };
    assert_eq!(
        content_value, received_content_value,
        "The received content {received_content_value:?}, must match the expected {content_value:?}",
    );
}
