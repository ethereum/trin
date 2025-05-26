use alloy::{
    consensus::{transaction::SignerRecoverable, TxEnvelope},
    eips::eip4895::Withdrawal,
};
use anyhow::anyhow;
use ethportal_api::{
    consensus::beacon_block::{
        SignedBeaconBlock, SignedBeaconBlockBellatrix, SignedBeaconBlockCapella,
        SignedBeaconBlockDeneb, SignedBeaconBlockElectra,
    },
    types::execution::builders::{block::decode_transactions, header::ExecutionHeaderBuilder},
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use super::types::{ProcessedBlock, TransactionsWithSender};

pub trait ProcessBeaconBlock {
    fn process_beacon_block(&self) -> anyhow::Result<ProcessedBlock>;
}

impl ProcessBeaconBlock for SignedBeaconBlock {
    fn process_beacon_block(&self) -> anyhow::Result<ProcessedBlock> {
        match self {
            SignedBeaconBlock::Bellatrix(block) => block.process_beacon_block(),
            SignedBeaconBlock::Capella(block) => block.process_beacon_block(),
            SignedBeaconBlock::Deneb(block) => block.process_beacon_block(),
            SignedBeaconBlock::Electra(block) => block.process_beacon_block(),
        }
    }
}

impl ProcessBeaconBlock for SignedBeaconBlockBellatrix {
    fn process_beacon_block(&self) -> anyhow::Result<ProcessedBlock> {
        let payload = &self.message.body.execution_payload;

        let transactions = decode_transactions(&payload.transactions)?;
        let header = ExecutionHeaderBuilder::bellatrix(payload, &transactions)?;
        let transactions = process_transactions(transactions)?;

        Ok(ProcessedBlock {
            header,
            uncles: None,
            withdrawals: None,
            transactions,
        })
    }
}

impl ProcessBeaconBlock for SignedBeaconBlockCapella {
    fn process_beacon_block(&self) -> anyhow::Result<ProcessedBlock> {
        let payload = &self.message.body.execution_payload;

        let transactions = decode_transactions(&payload.transactions)?;
        let withdrawals: Vec<Withdrawal> =
            payload.withdrawals.iter().map(Withdrawal::from).collect();
        let header = ExecutionHeaderBuilder::capella(payload, &transactions, &withdrawals)?;
        let transactions = process_transactions(transactions)?;

        Ok(ProcessedBlock {
            header,
            uncles: None,
            withdrawals: Some(withdrawals),
            transactions,
        })
    }
}

impl ProcessBeaconBlock for SignedBeaconBlockDeneb {
    fn process_beacon_block(&self) -> anyhow::Result<ProcessedBlock> {
        let payload = &self.message.body.execution_payload;

        let transactions = decode_transactions(&payload.transactions)?;
        let withdrawals: Vec<Withdrawal> =
            payload.withdrawals.iter().map(Withdrawal::from).collect();
        let header = ExecutionHeaderBuilder::deneb(
            payload,
            self.message.parent_root,
            &transactions,
            &withdrawals,
        )?;
        let transactions = process_transactions(transactions)?;

        Ok(ProcessedBlock {
            header,
            uncles: None,
            withdrawals: Some(withdrawals),
            transactions,
        })
    }
}

impl ProcessBeaconBlock for SignedBeaconBlockElectra {
    fn process_beacon_block(&self) -> anyhow::Result<ProcessedBlock> {
        let payload = &self.message.body.execution_payload;

        let transactions = decode_transactions(&payload.transactions)?;
        let withdrawals: Vec<Withdrawal> =
            payload.withdrawals.iter().map(Withdrawal::from).collect();
        let header = ExecutionHeaderBuilder::electra(
            payload,
            self.message.parent_root,
            &transactions,
            &withdrawals,
            &self.message.body.execution_requests,
        )?;
        let transactions = process_transactions(transactions)?;

        Ok(ProcessedBlock {
            header: header.clone(),
            uncles: None,
            withdrawals: Some(withdrawals),
            transactions,
        })
    }
}

fn process_transactions(
    transactions: Vec<TxEnvelope>,
) -> anyhow::Result<Vec<TransactionsWithSender>> {
    transactions
        .into_par_iter()
        .map(|transaction| {
            transaction
                .recover_signer_unchecked()
                .map(|sender_address| TransactionsWithSender {
                    sender_address,
                    transaction,
                })
                .map_err(|err| anyhow!("Failed to recover signer: {err:?}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy::{
        consensus::Header,
        primitives::{Address, Bloom, B256, B64, U256},
    };
    use ethportal_api::consensus::{beacon_block::SignedBeaconBlock, fork::ForkName};

    use crate::e2hs::beacon::ProcessBeaconBlock;

    #[tokio::test]
    async fn process_beacon_block() {
        let signed_beacon_block_for_execution_block_15537397 =
            std::fs::read("../../test_assets/beacon/bellatrix/ValidSignedBeaconBlock/signed_beacon_block_15537397.ssz").unwrap();
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
            ommers_hash: B256::from_str(
                "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            )
            .unwrap(),
            beneficiary: Address::from_str("0xe688b84b23f322a994a53dbf8e15fa82cdb71127").unwrap(),
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
            gas_limit: 30000000,
            gas_used: 29997984,
            timestamp: 1663224215,
            extra_data: vec![].into(),
            mix_hash:
                B256::from_str(
                    "0x314347f2c9e35686c6e62dc10c232b911a34b9f25db0f925a1b2207014fb67c5",
                )
                .unwrap(),
            nonce:B64::ZERO,
            base_fee_per_gas: Some(69471578228),
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
            requests_hash: None,
        };

        assert_eq!(processed_block.header, expected);

        assert_eq!(
            processed_block.header.hash_slow(),
            B256::from_str("0x9797d65f12465ada68cdacf7e6b7c22fe43a4d09671187c1cb819e9b0e0dedf6")
                .unwrap()
        )
    }
}
