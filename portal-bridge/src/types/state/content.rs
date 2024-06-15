use alloy_primitives::{keccak256, B256};
use anyhow::anyhow;
use ethportal_api::{
    types::{
        content_key::state::{AccountTrieNodeKey, ContractBytecodeKey, ContractStorageTrieNodeKey},
        content_value::state::{
            AccountTrieNodeWithProof, ContractBytecodeWithProof, ContractStorageTrieNodeWithProof,
        },
        state_trie::nibbles::Nibbles,
    },
    StateContentKey, StateContentValue,
};
use revm_primitives::{Address, Bytecode};

use super::types::trie_proof::TrieProof;

pub fn create_account_content_key(account_proof: &TrieProof) -> anyhow::Result<StateContentKey> {
    let last_node = account_proof
        .proof
        .last()
        .ok_or(anyhow!("Missing proof!"))?;

    Ok(StateContentKey::AccountTrieNode(AccountTrieNodeKey {
        path: Nibbles::try_from_unpacked_nibbles(&account_proof.path)?,
        node_hash: keccak256(last_node),
    }))
}

pub fn create_account_content_value(
    block_hash: B256,
    account_proof: &TrieProof,
) -> anyhow::Result<StateContentValue> {
    Ok(StateContentValue::AccountTrieNodeWithProof(
        AccountTrieNodeWithProof {
            proof: account_proof.into(),
            block_hash,
        },
    ))
}

pub fn create_contract_content_key(
    address: Address,
    code_hash: B256,
) -> anyhow::Result<StateContentKey> {
    Ok(StateContentKey::ContractBytecode(ContractBytecodeKey {
        address,
        code_hash,
    }))
}

pub fn create_contract_content_value(
    block_hash: B256,
    account_proof: &TrieProof,
    code: Bytecode,
) -> anyhow::Result<StateContentValue> {
    Ok(StateContentValue::ContractBytecodeWithProof(
        ContractBytecodeWithProof {
            block_hash,
            code: code.bytecode.to_vec().into(),
            account_proof: account_proof.into(),
        },
    ))
}

pub fn create_storage_content_key(
    storage_proof: &TrieProof,
    address: Address,
) -> anyhow::Result<StateContentKey> {
    let last_node = storage_proof
        .proof
        .last()
        .ok_or(anyhow!("Missing proof!"))?;

    Ok(StateContentKey::ContractStorageTrieNode(
        ContractStorageTrieNodeKey {
            path: Nibbles::try_from_unpacked_nibbles(&storage_proof.path)?,
            node_hash: keccak256(last_node),
            address,
        },
    ))
}

pub fn create_storage_content_value(
    block_hash: B256,
    account_proof: &TrieProof,
    storage_proof: &TrieProof,
) -> anyhow::Result<StateContentValue> {
    Ok(StateContentValue::ContractStorageTrieNodeWithProof(
        ContractStorageTrieNodeWithProof {
            block_hash,
            storage_proof: storage_proof.into(),
            account_proof: account_proof.into(),
        },
    ))
}
