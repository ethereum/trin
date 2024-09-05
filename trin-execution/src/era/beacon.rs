use alloy_primitives::{Bloom, B64, U64};
use alloy_rlp::Decodable;
use ethportal_api::{
    consensus::{
        beacon_block::{
            SignedBeaconBlock, SignedBeaconBlockBellatrix, SignedBeaconBlockCapella,
            SignedBeaconBlockDeneb,
        },
        body::Transactions,
    },
    types::execution::transaction::Transaction,
    Header,
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use revm_primitives::{b256, B256, U256};

use super::types::{ProcessedBlock, TransactionsWithSender};

const EMPTY_UNCLE_ROOT_HASH: B256 =
    b256!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347");

pub trait ProcessBeaconBlock {
    fn process_beacon_block(&self) -> anyhow::Result<ProcessedBlock>;
}

impl ProcessBeaconBlock for SignedBeaconBlock {
    fn process_beacon_block(&self) -> anyhow::Result<ProcessedBlock> {
        match self {
            SignedBeaconBlock::Bellatrix(block) => block.process_beacon_block(),
            SignedBeaconBlock::Capella(block) => block.process_beacon_block(),
            SignedBeaconBlock::Deneb(block) => block.process_beacon_block(),
        }
    }
}

impl ProcessBeaconBlock for SignedBeaconBlockBellatrix {
    fn process_beacon_block(&self) -> anyhow::Result<ProcessedBlock> {
        let payload = &self.message.body.execution_payload;
        let header = Header {
            parent_hash: payload.parent_hash,
            uncles_hash: EMPTY_UNCLE_ROOT_HASH,
            author: payload.fee_recipient,
            state_root: payload.state_root,
            transactions_root: payload.transaction_root(),
            receipts_root: payload.receipts_root,
            logs_bloom: Bloom::from_slice(payload.logs_bloom.to_vec().as_slice()),
            difficulty: U256::ZERO,
            number: payload.block_number,
            gas_limit: U256::from(payload.gas_limit),
            gas_used: U256::from(payload.gas_used),
            timestamp: payload.timestamp,
            extra_data: payload.extra_data.to_vec(),
            mix_hash: Some(payload.prev_randao),
            nonce: Some(B64::ZERO),
            base_fee_per_gas: Some(payload.base_fee_per_gas),
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
        };

        Ok(ProcessedBlock {
            header: header.clone(),
            uncles: None,
            transactions: process_transactions(&payload.transactions)?,
        })
    }
}

impl ProcessBeaconBlock for SignedBeaconBlockCapella {
    fn process_beacon_block(&self) -> anyhow::Result<ProcessedBlock> {
        let payload = &self.message.body.execution_payload;
        let header = Header {
            parent_hash: payload.parent_hash,
            uncles_hash: EMPTY_UNCLE_ROOT_HASH,
            author: payload.fee_recipient,
            state_root: payload.state_root,
            transactions_root: payload.transaction_root(),
            receipts_root: payload.receipts_root,
            logs_bloom: Bloom::from_slice(payload.logs_bloom.to_vec().as_slice()),
            difficulty: U256::ZERO,
            number: payload.block_number,
            gas_limit: U256::from(payload.gas_limit),
            gas_used: U256::from(payload.gas_used),
            timestamp: payload.timestamp,
            extra_data: payload.extra_data.to_vec(),
            mix_hash: Some(payload.prev_randao),
            nonce: Some(B64::ZERO),
            base_fee_per_gas: Some(payload.base_fee_per_gas),
            withdrawals_root: Some(payload.withdrawals_root()),
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
        };

        Ok(ProcessedBlock {
            header: header.clone(),
            uncles: None,
            transactions: process_transactions(&payload.transactions)?,
        })
    }
}

impl ProcessBeaconBlock for SignedBeaconBlockDeneb {
    fn process_beacon_block(&self) -> anyhow::Result<ProcessedBlock> {
        let payload = &self.message.body.execution_payload;
        let header = Header {
            parent_hash: payload.parent_hash,
            uncles_hash: EMPTY_UNCLE_ROOT_HASH,
            author: payload.fee_recipient,
            state_root: payload.state_root,
            transactions_root: payload.transaction_root(),
            receipts_root: payload.receipts_root,
            logs_bloom: Bloom::from_slice(payload.logs_bloom.to_vec().as_slice()),
            difficulty: U256::ZERO,
            number: payload.block_number,
            gas_limit: U256::from(payload.gas_limit),
            gas_used: U256::from(payload.gas_used),
            timestamp: payload.timestamp,
            extra_data: payload.extra_data.to_vec(),
            mix_hash: Some(payload.prev_randao),
            nonce: Some(B64::ZERO),
            base_fee_per_gas: Some(payload.base_fee_per_gas),
            withdrawals_root: Some(payload.withdrawals_root()),
            blob_gas_used: Some(U64::from(payload.blob_gas_used)),
            excess_blob_gas: Some(U64::from(payload.excess_blob_gas)),
            parent_beacon_block_root: None,
        };

        Ok(ProcessedBlock {
            header: header.clone(),
            uncles: None,
            transactions: process_transactions(&payload.transactions)?,
        })
    }
}

fn process_transactions(
    transactions: &Transactions,
) -> anyhow::Result<Vec<TransactionsWithSender>> {
    transactions
        .into_par_iter()
        .map(|raw_tx| {
            let transaction = Transaction::decode(&mut raw_tx.to_vec().as_slice())
                .map_err(|err| anyhow::anyhow!("Failed decoding transaction rlp: {err:?}"))?;
            transaction
                .get_transaction_sender_address()
                .map(|sender_address| TransactionsWithSender {
                    sender_address,
                    transaction,
                })
        })
        .collect::<anyhow::Result<Vec<_>>>()
}
