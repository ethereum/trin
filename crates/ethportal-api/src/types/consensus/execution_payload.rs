use alloy::primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_u64;
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, typenum::U16, FixedVector, VariableList};
use superstruct::superstruct;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use super::serde::{de_hex_to_txs, de_number_to_u256, se_hex_to_number, se_txs_to_hex};
use crate::{
    types::{
        bytes::ByteList32,
        consensus::{body::Transactions, fork::ForkName, proof::build_merkle_proof_for_index},
    },
    utils::serde::{hex_fixed_vec, hex_var_list},
};

pub type Bloom = FixedVector<u8, typenum::U256>;
pub type ExtraData = ByteList32;

#[superstruct(
    variants(Bellatrix, Capella, Deneb),
    variant_attributes(
        derive(
            Default,
            Debug,
            Clone,
            PartialEq,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
        ),
        serde(deny_unknown_fields),
    )
)]
#[derive(Debug, Clone, Serialize, Encode, Deserialize, TreeHash)]
#[serde(untagged)]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct ExecutionPayload {
    pub parent_hash: B256,
    pub fee_recipient: Address,
    pub state_root: B256,
    pub receipts_root: B256,
    #[serde(with = "hex_fixed_vec")]
    pub logs_bloom: Bloom,
    pub prev_randao: B256, // 'difficulty' in the yellow paper
    #[serde(deserialize_with = "as_u64")]
    pub block_number: u64, // 'number' in the yellow paper
    #[serde(deserialize_with = "as_u64")]
    pub gas_limit: u64,
    #[serde(deserialize_with = "as_u64")]
    pub gas_used: u64,
    #[serde(deserialize_with = "as_u64")]
    pub timestamp: u64,
    #[serde(with = "hex_var_list")]
    pub extra_data: ExtraData,
    #[serde(deserialize_with = "de_number_to_u256")]
    #[serde(serialize_with = "se_hex_to_number")]
    pub base_fee_per_gas: U256,
    // Extra payload fields
    pub block_hash: B256, // Hash of execution block
    #[serde(serialize_with = "se_txs_to_hex")]
    #[serde(deserialize_with = "de_hex_to_txs")]
    pub transactions: Transactions,
    #[superstruct(only(Capella, Deneb))]
    pub withdrawals: VariableList<Withdrawal, U16>,
    #[superstruct(only(Deneb))]
    #[serde(deserialize_with = "as_u64")]
    pub blob_gas_used: u64,
    #[superstruct(only(Deneb))]
    #[serde(deserialize_with = "as_u64")]
    pub excess_blob_gas: u64,
}

impl ExecutionPayload {
    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Bellatrix => {
                ExecutionPayloadBellatrix::from_ssz_bytes(bytes).map(Self::Bellatrix)
            }
            ForkName::Capella => ExecutionPayloadCapella::from_ssz_bytes(bytes).map(Self::Capella),
            ForkName::Deneb => ExecutionPayloadDeneb::from_ssz_bytes(bytes).map(Self::Deneb),
        }
    }
}

impl ExecutionPayloadCapella {
    pub fn build_block_hash_proof(&self) -> Vec<B256> {
        let leaves = vec![
            self.parent_hash.tree_hash_root().0,
            self.fee_recipient.tree_hash_root().0,
            self.state_root.tree_hash_root().0,
            self.receipts_root.tree_hash_root().0,
            self.logs_bloom.tree_hash_root().0,
            self.prev_randao.tree_hash_root().0,
            self.block_number.tree_hash_root().0,
            self.gas_limit.tree_hash_root().0,
            self.gas_used.tree_hash_root().0,
            self.timestamp.tree_hash_root().0,
            self.extra_data.tree_hash_root().0,
            self.base_fee_per_gas.tree_hash_root().0,
            self.block_hash.tree_hash_root().0,
            self.transactions.tree_hash_root().0,
            self.withdrawals.tree_hash_root().0,
        ];
        build_merkle_proof_for_index(leaves, 12)
    }
}

impl ExecutionPayloadBellatrix {
    pub fn build_block_hash_proof(&self) -> Vec<B256> {
        let leaves = vec![
            self.parent_hash.tree_hash_root().0,
            self.fee_recipient.tree_hash_root().0,
            self.state_root.tree_hash_root().0,
            self.receipts_root.tree_hash_root().0,
            self.logs_bloom.tree_hash_root().0,
            self.prev_randao.tree_hash_root().0,
            self.block_number.tree_hash_root().0,
            self.gas_limit.tree_hash_root().0,
            self.gas_used.tree_hash_root().0,
            self.timestamp.tree_hash_root().0,
            self.extra_data.tree_hash_root().0,
            self.base_fee_per_gas.tree_hash_root().0,
            self.block_hash.tree_hash_root().0,
            self.transactions.tree_hash_root().0,
        ];
        build_merkle_proof_for_index(leaves, 12)
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct Withdrawal {
    #[serde(deserialize_with = "as_u64")]
    pub index: u64,
    #[serde(deserialize_with = "as_u64")]
    pub validator_index: u64,
    pub address: Address,
    #[serde(deserialize_with = "as_u64")]
    pub amount: u64,
}

#[superstruct(
    variants(Bellatrix, Capella, Deneb),
    variant_attributes(derive(
        Default,
        Debug,
        Clone,
        PartialEq,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        TreeHash
    ),)
)]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, TreeHash)]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct ExecutionPayloadHeader {
    #[superstruct(getter(copy))]
    pub parent_hash: B256,
    pub fee_recipient: Address,
    #[superstruct(getter(copy))]
    pub state_root: B256,
    #[superstruct(getter(copy))]
    pub receipts_root: B256,
    #[serde(with = "hex_fixed_vec")]
    pub logs_bloom: Bloom,
    #[superstruct(getter(copy))]
    pub prev_randao: B256,
    #[superstruct(getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub block_number: u64,
    #[superstruct(getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub gas_limit: u64,
    #[superstruct(getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub gas_used: u64,
    #[superstruct(getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub timestamp: u64,
    #[serde(with = "hex_var_list")]
    pub extra_data: ExtraData,
    #[superstruct(getter(copy))]
    #[serde(deserialize_with = "de_number_to_u256")]
    #[serde(serialize_with = "se_hex_to_number")]
    pub base_fee_per_gas: U256,
    #[superstruct(getter(copy))]
    pub block_hash: B256,
    #[superstruct(getter(copy))]
    pub transactions_root: B256,
    #[superstruct(only(Capella, Deneb))]
    #[superstruct(getter(copy))]
    pub withdrawals_root: B256,
    #[superstruct(only(Deneb))]
    #[superstruct(getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub blob_gas_used: u64,
    #[superstruct(only(Deneb))]
    #[superstruct(getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub excess_blob_gas: u64,
}

impl ExecutionPayloadHeader {
    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Bellatrix => {
                ExecutionPayloadHeaderBellatrix::from_ssz_bytes(bytes).map(Self::Bellatrix)
            }
            ForkName::Capella => {
                ExecutionPayloadHeaderCapella::from_ssz_bytes(bytes).map(Self::Capella)
            }
            ForkName::Deneb => ExecutionPayloadHeaderDeneb::from_ssz_bytes(bytes).map(Self::Deneb),
        }
    }
}
