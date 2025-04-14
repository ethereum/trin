use alloy::{
    consensus::{
        proofs::{calculate_transaction_root, calculate_withdrawals_root},
        Header, TxEnvelope,
    },
    eips::eip4895::Withdrawal,
    primitives::{Bloom, B64, U256},
};
use anyhow::ensure;
use ethportal_api::types::consensus::execution_payload::{
    ExecutionPayloadBellatrix, ExecutionPayloadCapella,
};
use trin_execution::era::beacon::EMPTY_UNCLE_ROOT_HASH;

pub fn pre_capella_execution_payload_to_header(
    payload: ExecutionPayloadBellatrix,
    transactions: &[TxEnvelope],
) -> anyhow::Result<Header> {
    let transactions_root = calculate_transaction_root(transactions);
    let header = Header {
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
    };

    ensure!(
        payload.block_hash == header.hash_slow(),
        "Block hash mismatch"
    );
    Ok(header)
}

pub fn pre_deneb_execution_payload_to_header(
    payload: ExecutionPayloadCapella,
    transactions: &[TxEnvelope],
    withdrawals: &[Withdrawal],
) -> anyhow::Result<Header> {
    let transactions_root = calculate_transaction_root(transactions);
    let withdrawals_root = calculate_withdrawals_root(withdrawals);
    let header = Header {
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
        withdrawals_root: Some(withdrawals_root),
        blob_gas_used: None,
        excess_blob_gas: None,
        parent_beacon_block_root: None,
        requests_hash: None,
    };

    ensure!(
        payload.block_hash == header.hash_slow(),
        "Block hash mismatch"
    );
    Ok(header)
}
