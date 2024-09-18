use crate::{
    utils::{
        fixtures_state_account_trie_node, fixtures_state_contract_bytecode,
        fixtures_state_contract_storage_trie_node, wait_for_state_content, StateFixture,
    },
    Peertest, PeertestNode,
};
use ethportal_api::{
    jsonrpsee::async_client::Client,
    types::execution::header_with_proof::{BlockHeaderProof, HeaderWithProof, SszNone},
    ContentValue, HistoryContentKey, HistoryContentValue, HistoryNetworkApiClient,
    StateNetworkApiClient,
};
use tracing::info;

pub async fn test_state_offer_account_trie_node(peertest: &Peertest, target: &Client) {
    for fixture in fixtures_state_account_trie_node() {
        info!(
            "Testing offering AccountTrieNode for key: {:?}",
            fixture.key
        );
        test_state_offer(&fixture, target, &peertest.bootnode).await;
    }
}

pub async fn test_state_gossip_contract_storage_trie_node(peertest: &Peertest, target: &Client) {
    for fixture in fixtures_state_contract_storage_trie_node() {
        info!(
            "Testing offering ContractStorageTrieNode for key: {:?}",
            fixture.key
        );
        test_state_offer(&fixture, target, &peertest.bootnode).await;
    }
}

pub async fn test_state_gossip_contract_bytecode(peertest: &Peertest, target: &Client) {
    for fixture in fixtures_state_contract_bytecode() {
        info!(
            "Testing offering ContractBytecode for key: {:?}",
            fixture.key
        );
        test_state_offer(&fixture, target, &peertest.bootnode).await;
    }
}

async fn test_state_offer(fixture: &StateFixture, target: &Client, peer: &PeertestNode) {
    // Make sure that peer has block header
    let history_content_key =
        HistoryContentKey::new_block_header_by_hash(fixture.block_header.hash());
    let history_content_value = HistoryContentValue::BlockHeaderWithProof(HeaderWithProof {
        header: fixture.block_header.clone(),
        proof: BlockHeaderProof::None(SszNone::default()),
    });
    HistoryNetworkApiClient::store(
        &peer.ipc_client,
        history_content_key,
        history_content_value.encode(),
    )
    .await
    .unwrap();

    // Offer state network content to peer
    StateNetworkApiClient::offer(
        target,
        peer.enr.clone(),
        fixture.key.clone(),
        fixture.raw_offer_value.clone(),
    )
    .await
    .unwrap();

    // Check that peer has state content
    let lookup_content_value = wait_for_state_content(&peer.ipc_client, fixture.key.clone()).await;
    assert_eq!(lookup_content_value, fixture.lookup_value());
}
