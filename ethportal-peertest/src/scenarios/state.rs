use crate::{
    utils::{
        fixtures_state_account_trie_node, fixtures_state_contract_bytecode,
        fixtures_state_contract_storage_trie_node, wait_for_state_content, StateFixture,
    },
    Peertest, PeertestNode,
};
use ethportal_api::{jsonrpsee::async_client::Client, StateNetworkApiClient};
use tracing::info;

pub async fn test_state_offer_account_trie_node(peertest: &Peertest, target: &Client) {
    for fixture in fixtures_state_account_trie_node() {
        info!(
            "Testing offering AccountTrieNode for key: {:?}",
            fixture.content_data.key
        );
        test_state_offer(&fixture, target, &peertest.bootnode).await;
    }
}

pub async fn test_state_gossip_contract_storage_trie_node(peertest: &Peertest, target: &Client) {
    for fixture in fixtures_state_contract_storage_trie_node() {
        info!(
            "Testing offering ContractStorageTrieNode for key: {:?}",
            fixture.content_data.key
        );
        test_state_offer(&fixture, target, &peertest.bootnode).await;
    }
}

pub async fn test_state_gossip_contract_bytecode(peertest: &Peertest, target: &Client) {
    for fixture in fixtures_state_contract_bytecode() {
        info!(
            "Testing offering ContractBytecode for key: {:?}",
            fixture.content_data.key
        );
        test_state_offer(&fixture, target, &peertest.bootnode).await;
    }
}

async fn test_state_offer(fixture: &StateFixture, target: &Client, peer: &PeertestNode) {
    target
        .offer(
            peer.enr.clone(),
            fixture.content_data.key.clone(),
            fixture.content_data.offer_value.clone(),
        )
        .await
        .unwrap();

    let lookup_content_value =
        wait_for_state_content(&peer.ipc_client, fixture.content_data.key.clone()).await;
    assert_eq!(lookup_content_value, fixture.content_data.lookup_value);
}
