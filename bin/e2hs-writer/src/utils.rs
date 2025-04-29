use std::{fs, path::Path};

use alloy::{
    consensus::{
        proofs::{calculate_transaction_root, calculate_withdrawals_root},
        Header, TxEnvelope,
    },
    eips::eip4895::Withdrawal,
    primitives::{Bloom, B256, B64, U256},
};
use anyhow::{anyhow, ensure};
use ethportal_api::{
    consensus::execution_payload::ExecutionPayloadDeneb,
    types::{
        consensus::execution_payload::{ExecutionPayloadBellatrix, ExecutionPayloadCapella},
        execution::accumulator::EpochAccumulator,
    },
    utils::bytes::hex_encode,
};
use ssz::Decode;
use trin_execution::era::beacon::EMPTY_UNCLE_ROOT_HASH;
use trin_validation::accumulator::PreMergeAccumulator;

pub fn bellatrix_execution_payload_to_header(
    payload: &ExecutionPayloadBellatrix,
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

pub fn capella_execution_payload_to_header(
    payload: &ExecutionPayloadCapella,
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

pub fn post_deneb_execution_payload_to_header(
    payload: &ExecutionPayloadDeneb,
    parent_beacon_block_root: B256,
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
        blob_gas_used: Some(payload.blob_gas_used),
        excess_blob_gas: Some(payload.excess_blob_gas),
        parent_beacon_block_root: Some(parent_beacon_block_root),
        requests_hash: None,
    };

    ensure!(
        payload.block_hash == header.hash_slow(),
        "Block hash mismatch"
    );
    Ok(header)
}

/// Lookup the epoch accumulator & epoch hash for the given epoch index.
pub async fn lookup_epoch_acc(
    epoch_index: u64,
    pre_merge_acc: &PreMergeAccumulator,
    epoch_acc_path: &Path,
) -> anyhow::Result<EpochAccumulator> {
    let epoch_hash = pre_merge_acc.historical_epochs[epoch_index as usize];
    let epoch_hash_pretty = hex_encode(epoch_hash);
    let epoch_hash_pretty = epoch_hash_pretty.trim_start_matches("0x");
    let epoch_acc_path = format!(
        "{}/bridge_content/0x03{epoch_hash_pretty}.portalcontent",
        epoch_acc_path.display(),
    );
    let epoch_acc = match fs::read(&epoch_acc_path) {
        Ok(val) => EpochAccumulator::from_ssz_bytes(&val).map_err(|err| anyhow!("{err:?}"))?,
        Err(_) => {
            return Err(anyhow!(
                "Unable to find local epoch acc at path: {epoch_acc_path:?}"
            ))
        }
    };
    Ok(epoch_acc)
}
