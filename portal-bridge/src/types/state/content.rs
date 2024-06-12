use alloy_primitives::{keccak256, B256};
use anyhow::anyhow;
use ethportal_api::{
    types::{
        content_key::state::AccountTrieNodeKey,
        content_value::state::AccountTrieNodeWithProof,
        state_trie::{nibbles::Nibbles, EncodedTrieNode, TrieProof},
    },
    StateContentKey, StateContentValue,
};

use super::trie_walker::AccountProof;

pub fn create_content_key(account_proof: &AccountProof) -> anyhow::Result<StateContentKey> {
    let last_node = account_proof
        .proof
        .last()
        .ok_or(anyhow!("Missing proof!"))?;
    let last_node_hash = keccak256(last_node);

    Ok(StateContentKey::AccountTrieNode(AccountTrieNodeKey {
        path: Nibbles::try_from_unpacked_nibbles(&account_proof.path)?,
        node_hash: last_node_hash,
    }))
}

pub fn create_content_value(
    block_hash: B256,
    account_proof: &AccountProof,
) -> anyhow::Result<StateContentValue> {
    let trie_proof = TrieProof::from(
        account_proof
            .proof
            .iter()
            .map(|bytes| EncodedTrieNode::from(bytes.to_vec()))
            .collect::<Vec<EncodedTrieNode>>(),
    );
    Ok(StateContentValue::AccountTrieNodeWithProof(
        AccountTrieNodeWithProof {
            proof: trie_proof,
            block_hash,
        },
    ))
}
