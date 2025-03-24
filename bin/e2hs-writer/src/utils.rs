use alloy::{
    consensus::Header,
    primitives::{Bloom, B64, U256},
};
use ethportal_api::types::consensus::execution_payload::{
    ExecutionPayloadBellatrix, ExecutionPayloadCapella,
};
use tree_hash::TreeHash;
use trin_execution::era::beacon::EMPTY_UNCLE_ROOT_HASH;

pub fn pre_capella_execution_payload_to_header(payload: ExecutionPayloadBellatrix) -> Header {
    let transactions_root = payload.transactions.tree_hash_root();
    Header {
        parent_hash: payload.parent_hash,
        ommers_hash: EMPTY_UNCLE_ROOT_HASH,
        beneficiary: payload.fee_recipient,
        state_root: payload.state_root,
        transactions_root,
        receipts_root: payload.receipts_root,
        logs_bloom: Bloom::from_slice(payload.logs_bloom.to_vec().as_slice()),
        difficulty: U256::ZERO,
        number: payload.block_number,
        gas_limit: payload.gas_limit,
        gas_used: payload.gas_used,
        timestamp: payload.timestamp,
        extra_data: payload.extra_data.to_vec().into(),
        mix_hash: payload.prev_randao,
        nonce: B64::ZERO,
        base_fee_per_gas: Some(payload.base_fee_per_gas.to()),
        withdrawals_root: None,
        blob_gas_used: None,
        excess_blob_gas: None,
        parent_beacon_block_root: None,
        requests_hash: None,
    }
}

pub fn pre_deneb_execution_payload_to_header(payload: ExecutionPayloadCapella) -> Header {
    let transactions_root = payload.transactions.tree_hash_root();
    let withdrawals_root = Some(payload.withdrawals.tree_hash_root());
    Header {
        parent_hash: payload.parent_hash,
        ommers_hash: EMPTY_UNCLE_ROOT_HASH,
        beneficiary: payload.fee_recipient,
        state_root: payload.state_root,
        transactions_root,
        receipts_root: payload.receipts_root,
        logs_bloom: Bloom::from_slice(payload.logs_bloom.to_vec().as_slice()),
        difficulty: U256::ZERO,
        number: payload.block_number,
        gas_limit: payload.gas_limit,
        gas_used: payload.gas_used,
        timestamp: payload.timestamp,
        extra_data: payload.extra_data.to_vec().into(),
        mix_hash: payload.prev_randao,
        nonce: B64::ZERO,
        base_fee_per_gas: Some(payload.base_fee_per_gas.to()),
        withdrawals_root,
        blob_gas_used: None,
        excess_blob_gas: None,
        parent_beacon_block_root: None,
        requests_hash: None,
    }
}
