use alloy_primitives::{keccak256, B256};
use anyhow::{anyhow, bail};
use ethportal_api::{
    types::{
        content_key::state::AccountTrieNodeKey,
        content_value::state::AccountTrieNodeWithProof,
        state_trie::{nibbles::Nibbles, EncodedTrieNode, TrieProof},
    },
    StateContentKey, StateContentValue,
};

use super::execution::AccountProof;

pub fn create_content_key(account_proof: &AccountProof) -> anyhow::Result<StateContentKey> {
    let last_node = account_proof
        .proof
        .last()
        .ok_or(anyhow!("Missing proof!"))?;
    let last_node_hash = keccak256(last_node);

    let eth_trie::node::Node::Leaf(last_node) = eth_trie::decode_node(&mut last_node.as_ref())?
    else {
        bail!("Last node in the proof should be leaf!")
    };
    let mut last_node_nibbles = last_node.key.clone();
    if last_node_nibbles.is_leaf() {
        last_node_nibbles.pop();
    } else {
        bail!("Nibbles of the last node should have LEAF Marker")
    }

    let mut path: Vec<u8> = keccak256(account_proof.address)
        .into_iter()
        .flat_map(|b| [b >> 4, b & 0xF])
        .collect();
    if path.ends_with(last_node_nibbles.get_data()) {
        path.truncate(path.len() - last_node_nibbles.len());
    } else {
        bail!("Path should have a suffix of last node's nibbles")
    }

    Ok(StateContentKey::AccountTrieNode(AccountTrieNodeKey {
        path: Nibbles::try_from_unpacked_nibbles(&path)?,
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
