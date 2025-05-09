use alloy::{
    consensus::BlockBody as AlloyBlockBody,
    eips::eip4895::{Withdrawal, Withdrawals},
};
use ethportal_api::{
    consensus::{
        beacon_block::{
            BeaconBlockBellatrix, BeaconBlockCapella, BeaconBlockDeneb, BeaconBlockElectra,
        },
        beacon_state::HistoricalBatch,
    },
    types::execution::{
        block_body::BlockBody,
        header_with_proof::{
            build_capella_historical_summaries_proof, build_deneb_historical_summaries_proof,
            build_electra_historical_summaries_proof, build_historical_roots_proof,
            BlockHeaderProof, HeaderWithProof,
        },
    },
};
use trin_execution::era::beacon::decode_transactions;

use super::execution_header_builder::ExecutionHeaderBuilder;

pub struct ExecutionBlockBuilder;

impl ExecutionBlockBuilder {
    pub fn bellatrix(
        block: &BeaconBlockBellatrix,
        historical_batch: &HistoricalBatch,
    ) -> anyhow::Result<(HeaderWithProof, BlockBody)> {
        let payload = &block.body.execution_payload;

        let transactions = decode_transactions(&payload.transactions)?;

        let header_with_proof = HeaderWithProof {
            header: ExecutionHeaderBuilder::bellatrix(payload, &transactions)?,
            proof: BlockHeaderProof::HistoricalRoots(build_historical_roots_proof(
                block.slot,
                historical_batch,
                block,
            )),
        };
        let body = BlockBody(AlloyBlockBody {
            transactions,
            ommers: vec![],
            withdrawals: None,
        });

        Ok((header_with_proof, body))
    }

    pub fn capella(
        block: &BeaconBlockCapella,
        historical_batch: &HistoricalBatch,
    ) -> anyhow::Result<(HeaderWithProof, BlockBody)> {
        let payload = &block.body.execution_payload;

        let transactions = decode_transactions(&payload.transactions)?;
        let withdrawals: Vec<Withdrawal> =
            payload.withdrawals.iter().map(Withdrawal::from).collect();

        let header_with_proof = HeaderWithProof {
            header: ExecutionHeaderBuilder::capella(payload, &transactions, &withdrawals)?,
            proof: BlockHeaderProof::HistoricalSummariesCapella(
                build_capella_historical_summaries_proof(
                    block.slot,
                    &historical_batch.block_roots,
                    block,
                ),
            ),
        };
        let body = BlockBody(AlloyBlockBody {
            transactions,
            ommers: vec![],
            withdrawals: Some(Withdrawals::new(withdrawals)),
        });

        Ok((header_with_proof, body))
    }

    pub fn deneb(
        block: &BeaconBlockDeneb,
        historical_batch: &HistoricalBatch,
    ) -> anyhow::Result<(HeaderWithProof, BlockBody)> {
        let payload = &block.body.execution_payload;

        let transactions = decode_transactions(&payload.transactions)?;
        let withdrawals: Vec<Withdrawal> =
            payload.withdrawals.iter().map(Withdrawal::from).collect();

        let header_with_proof = HeaderWithProof {
            header: ExecutionHeaderBuilder::deneb(
                payload,
                block.parent_root,
                &transactions,
                &withdrawals,
            )?,
            proof: BlockHeaderProof::HistoricalSummariesDeneb(
                build_deneb_historical_summaries_proof(
                    block.slot,
                    &historical_batch.block_roots,
                    block,
                ),
            ),
        };
        let body = BlockBody(AlloyBlockBody {
            transactions,
            ommers: vec![],
            withdrawals: Some(Withdrawals::new(withdrawals)),
        });

        Ok((header_with_proof, body))
    }

    pub fn electra(
        block: &BeaconBlockElectra,
        historical_batch: &HistoricalBatch,
    ) -> anyhow::Result<(HeaderWithProof, BlockBody)> {
        let payload = &block.body.execution_payload;

        let transactions = decode_transactions(&payload.transactions)?;
        let withdrawals: Vec<Withdrawal> =
            payload.withdrawals.iter().map(Withdrawal::from).collect();

        let header_with_proof = HeaderWithProof {
            header: ExecutionHeaderBuilder::electra(
                payload,
                block.parent_root,
                &transactions,
                &withdrawals,
                &block.body.execution_requests,
            )?,
            proof: BlockHeaderProof::HistoricalSummariesDeneb(
                build_electra_historical_summaries_proof(
                    block.slot,
                    &historical_batch.block_roots,
                    block,
                ),
            ),
        };
        let body = BlockBody(AlloyBlockBody {
            transactions,
            ommers: vec![],
            withdrawals: Some(Withdrawals::new(withdrawals)),
        });

        Ok((header_with_proof, body))
    }
}
