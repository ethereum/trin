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
    types::execution::{transaction::Transaction, withdrawal::Withdrawal},
    utils::roots::calculate_merkle_patricia_root,
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

        let transactions = process_transactions(&payload.transactions)?;
        let transactions_root = calculate_merkle_patricia_root(
            transactions
                .iter()
                .map(|transaction| &transaction.transaction),
        )?;

        let header = Header {
            parent_hash: payload.parent_hash,
            uncles_hash: EMPTY_UNCLE_ROOT_HASH,
            author: payload.fee_recipient,
            state_root: payload.state_root,
            transactions_root,
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
            withdrawals: None,
            transactions,
        })
    }
}

impl ProcessBeaconBlock for SignedBeaconBlockCapella {
    fn process_beacon_block(&self) -> anyhow::Result<ProcessedBlock> {
        let payload = &self.message.body.execution_payload;

        let transactions = process_transactions(&payload.transactions)?;
        let transactions_root = calculate_merkle_patricia_root(
            transactions
                .iter()
                .map(|transaction| &transaction.transaction),
        )?;

        let withdrawals: Vec<Withdrawal> =
            payload.withdrawals.iter().map(Withdrawal::from).collect();
        let withdrawals_root = calculate_merkle_patricia_root(&withdrawals)?;

        let header = Header {
            parent_hash: payload.parent_hash,
            uncles_hash: EMPTY_UNCLE_ROOT_HASH,
            author: payload.fee_recipient,
            state_root: payload.state_root,
            transactions_root,
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
            withdrawals_root: Some(withdrawals_root),
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
        };

        Ok(ProcessedBlock {
            header: header.clone(),
            uncles: None,
            withdrawals: Some(withdrawals),
            transactions,
        })
    }
}

impl ProcessBeaconBlock for SignedBeaconBlockDeneb {
    fn process_beacon_block(&self) -> anyhow::Result<ProcessedBlock> {
        let payload = &self.message.body.execution_payload;

        let transactions = process_transactions(&payload.transactions)?;
        let transactions_root = calculate_merkle_patricia_root(
            transactions
                .iter()
                .map(|transaction| &transaction.transaction),
        )?;

        let withdrawals: Vec<Withdrawal> =
            payload.withdrawals.iter().map(Withdrawal::from).collect();
        let withdrawals_root = calculate_merkle_patricia_root(&withdrawals)?;

        let header = Header {
            parent_hash: payload.parent_hash,
            uncles_hash: EMPTY_UNCLE_ROOT_HASH,
            author: payload.fee_recipient,
            state_root: payload.state_root,
            transactions_root,
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
            withdrawals_root: Some(withdrawals_root),
            blob_gas_used: Some(U64::from(payload.blob_gas_used)),
            excess_blob_gas: Some(U64::from(payload.excess_blob_gas)),
            parent_beacon_block_root: None,
        };

        Ok(ProcessedBlock {
            header: header.clone(),
            uncles: None,
            withdrawals: Some(withdrawals),
            transactions,
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy_primitives::{Address, Bloom, B256, B64, U256};
    use ethportal_api::{
        consensus::{beacon_block::SignedBeaconBlock, fork::ForkName},
        Header,
    };

    use crate::era::beacon::ProcessBeaconBlock;

    #[tokio::test]
    async fn process_beacon_block() {
        let signed_beacon_block_for_execution_block_15537397 =
            std::fs::read("../test_assets/beacon/bellatrix/ValidSignedBeaconBlock/signed_beacon_block_15537397.ssz").unwrap();
        let signed_beacon_block = SignedBeaconBlock::from_ssz_bytes(
            &signed_beacon_block_for_execution_block_15537397,
            ForkName::Bellatrix,
        )
        .unwrap();

        let processed_block = signed_beacon_block.process_beacon_block().unwrap();
        let expected: Header = Header {
            parent_hash: B256::from_str(
                "0x98c735877f2f30bad54fc46ba8bcd93a54da32a60b2905cb23ad6c7a70ebaa40",
            )
            .unwrap(),
            uncles_hash: B256::from_str(
                "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            )
            .unwrap(),
            author: Address::from_str("0xe688b84b23f322a994a53dbf8e15fa82cdb71127").unwrap(),
            state_root: B256::from_str(
                "0x2c1728ed8e5d59c813fae703638b359fd13f0c58270f8f179f82478e72097684",
            )
            .unwrap(),
            transactions_root: B256::from_str(
                "0x165a029503ae62a153a3b9589a09db72646749266b2b5fa9ba3198eef453e670",
            )
            .unwrap(),
            receipts_root: B256::from_str(
                "0x20cebf97b0024253e3e959ed681c5c659d44a13e94eef442a23667efcba0ed67",
            )
            .unwrap(),
            logs_bloom: Bloom::from_str("0x10000905a11025401e40204209111c0d8401a63a20024102066201864f8000081001004812102b4200400a0080001710666011200f48a08824201c0092a3e170d03e1800d65080186d21000908a00621100a260408d06384008711449148111002880a00e2002a1089491810a00249d80100113c04a506ccb69003b1a00c00c0009c8520012632848b090500012000889816342101cdc14d0512278204308004424061ca18107c08000882e084606902218042290a11122a58688e50184a0a0169820b436048301005180243488a040480249060802800582004451b1404212a141930280214d8140421110024a14e4816048703025147c48208499420a10328").unwrap(),
            difficulty: U256::ZERO,
            number: 15537397,
            gas_limit: U256::from(30000000),
            gas_used: U256::from(29997984),
            timestamp: 1663224215,
            extra_data: vec![],
            mix_hash: Some(
                B256::from_str(
                    "0x314347f2c9e35686c6e62dc10c232b911a34b9f25db0f925a1b2207014fb67c5",
                )
                .unwrap(),
            ),
            nonce: Some(B64::ZERO),
            base_fee_per_gas: Some(U256::from(69471578228_u128)),
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
        };

        assert_eq!(processed_block.header, expected);

        assert_eq!(
            processed_block.header.hash(),
            B256::from_str("0x9797d65f12465ada68cdacf7e6b7c22fe43a4d09671187c1cb819e9b0e0dedf6")
                .unwrap()
        )
    }
}
