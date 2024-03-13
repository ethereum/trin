use crate::{
    utils::{
        fixtures_state_account_trie_node, fixtures_state_contract_bytecode,
        fixtures_state_contract_storage_trie_node, fixtures_state_recursive_gossip,
        wait_for_state_content, StateFixture,
    },
    Peertest, PeertestNode,
};
use ethportal_api::{
    jsonrpsee::async_client::Client, types::content_value::state::TrieNode, StateContentValue,
    StateNetworkApiClient,
};
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
            Some(fixture.content_data.offer_value.clone()),
        )
        .await
        .unwrap();

    let lookup_content_value =
        wait_for_state_content(&peer.ipc_client, fixture.content_data.key.clone()).await;
    assert_eq!(lookup_content_value, fixture.content_data.lookup_value);
}

pub async fn test_state_recursive_gossip(peertest: &Peertest, target: &Client) {
    let _ = target.ping(peertest.bootnode.enr.clone()).await.unwrap();

    for fixture in fixtures_state_recursive_gossip().unwrap() {
        let (first_key, first_value) = &fixture.key_value_pairs.first().unwrap();
        info!(
            "Testing recursive gossip starting with key: {:?}",
            first_key
        );

        target
            .gossip(first_key.clone(), first_value.clone())
            .await
            .unwrap();

        // Verify that every key/value is fully propagated
        for (key, value) in fixture.key_value_pairs {
            let expected_lookup_trie_node = match value {
                StateContentValue::AccountTrieNodeWithProof(value) => {
                    value.proof.last().unwrap().clone()
                }
                StateContentValue::ContractStorageTrieNodeWithProof(value) => {
                    value.storage_proof.last().unwrap().clone()
                }
                _ => panic!("Unexpected state content value: {value:?}"),
            };
            let expected_lookup_value = StateContentValue::TrieNode(TrieNode {
                node: expected_lookup_trie_node,
            });

            assert_eq!(
                wait_for_state_content(target, key.clone()).await,
                expected_lookup_value,
                "Expecting lookup for {key:?} to return {expected_lookup_value:?}"
            );
        }
    }
}
