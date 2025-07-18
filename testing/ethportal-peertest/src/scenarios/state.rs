use alloy_hardforks::EthereumHardforks;
use ethportal_api::{
    jsonrpsee::async_client::Client,
    types::{
        execution::header_with_proof::{
            BlockHeaderProof, BlockProofHistoricalRoots, BlockProofHistoricalSummariesCapella,
            HeaderWithProof,
        },
        network_spec::network_spec,
    },
    ContentValue, LegacyHistoryContentKey, LegacyHistoryContentValue,
    LegacyHistoryNetworkApiClient, StateNetworkApiClient,
};
use tracing::info;

use crate::{
    utils::{
        fixtures_state_account_trie_node, fixtures_state_contract_bytecode,
        fixtures_state_contract_storage_trie_node, wait_for_state_content, StateFixture,
    },
    Peertest, PeertestNode,
};

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
    let legacy_history_content_key =
        LegacyHistoryContentKey::new_block_header_by_hash(fixture.block_header.hash_slow());

    let proof = if network_spec().is_shanghai_active_at_timestamp(fixture.block_header.timestamp) {
        BlockHeaderProof::HistoricalSummariesCapella(BlockProofHistoricalSummariesCapella {
            beacon_block_proof: Default::default(),
            beacon_block_root: Default::default(),
            execution_block_proof: Default::default(),
            slot: 0,
        })
    } else if network_spec().is_paris_active_at_block(fixture.block_header.number) {
        BlockHeaderProof::HistoricalRoots(BlockProofHistoricalRoots {
            beacon_block_proof: Default::default(),
            beacon_block_root: Default::default(),
            execution_block_proof: Default::default(),
            slot: 0,
        })
    } else {
        BlockHeaderProof::HistoricalHashes(Default::default())
    };

    let legacy_history_content_value =
        LegacyHistoryContentValue::BlockHeaderWithProof(HeaderWithProof {
            header: fixture.block_header.clone(),
            proof: proof.clone(),
        });

    LegacyHistoryNetworkApiClient::store(
        &peer.ipc_client,
        legacy_history_content_key,
        legacy_history_content_value.encode(),
    )
    .await
    .unwrap();

    // Offer state network content to peer
    StateNetworkApiClient::offer(
        target,
        peer.enr.clone(),
        vec![(fixture.key.clone(), fixture.raw_offer_value.clone())],
    )
    .await
    .unwrap();

    // Check that peer has state content
    let lookup_content_value = wait_for_state_content(&peer.ipc_client, fixture.key.clone()).await;
    assert_eq!(lookup_content_value, fixture.lookup_value());
}
