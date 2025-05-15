use alloy::{
    consensus::{
        proofs::{calculate_transaction_root, calculate_withdrawals_root},
        Header, TxEnvelope, EMPTY_OMMER_ROOT_HASH,
    },
    eips::eip4895::Withdrawal,
    primitives::{Bloom, B256, B64, U256},
};
use anyhow::ensure;

use crate::consensus::{
    execution_payload::{
        ExecutionPayloadBellatrix, ExecutionPayloadCapella, ExecutionPayloadDeneb,
        ExecutionPayloadElectra,
    },
    execution_requests::ExecutionRequests,
};

pub struct ExecutionHeaderBuilder;

impl ExecutionHeaderBuilder {
    pub fn bellatrix(
        payload: &ExecutionPayloadBellatrix,
        transactions: &[TxEnvelope],
    ) -> anyhow::Result<Header> {
        let transactions_root = calculate_transaction_root(transactions);
        let header = Header {
            parent_hash: payload.parent_hash,
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
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

    pub fn capella(
        payload: &ExecutionPayloadCapella,
        transactions: &[TxEnvelope],
        withdrawals: &[Withdrawal],
    ) -> anyhow::Result<Header> {
        let transactions_root = calculate_transaction_root(transactions);
        let withdrawals_root = calculate_withdrawals_root(withdrawals);
        let header = Header {
            parent_hash: payload.parent_hash,
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
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

    pub fn deneb(
        payload: &ExecutionPayloadDeneb,
        parent_beacon_block_root: B256,
        transactions: &[TxEnvelope],
        withdrawals: &[Withdrawal],
    ) -> anyhow::Result<Header> {
        let transactions_root = calculate_transaction_root(transactions);
        let withdrawals_root = calculate_withdrawals_root(withdrawals);
        let header = Header {
            parent_hash: payload.parent_hash,
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
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

    pub fn electra(
        payload: &ExecutionPayloadElectra,
        parent_beacon_block_root: B256,
        transactions: &[TxEnvelope],
        withdrawals: &[Withdrawal],
        requests: &ExecutionRequests,
    ) -> anyhow::Result<Header> {
        let transactions_root = calculate_transaction_root(transactions);
        let withdrawals_root = calculate_withdrawals_root(withdrawals);
        let header = Header {
            parent_hash: payload.parent_hash,
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
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
            requests_hash: Some(requests.requests_hash()),
        };

        ensure!(
            payload.block_hash == header.hash_slow(),
            "Block hash mismatch"
        );
        Ok(header)
    }
}
