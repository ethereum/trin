use alloy::{
    consensus::{BlockBody as AlloyBlockBody, TxEnvelope},
    eips::eip4895::{Withdrawal, Withdrawals},
};
use alloy_rlp::Decodable;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use super::execution_header_builder::ExecutionHeaderBuilder;
use crate::{
    consensus::{
        beacon_block::{
            BeaconBlockBellatrix, BeaconBlockCapella, BeaconBlockDeneb, BeaconBlockElectra,
        },
        beacon_state::HistoricalBatch,
        body::Transactions,
    },
    types::execution::header_with_proof::{
        build_capella_historical_summaries_proof, build_deneb_historical_summaries_proof,
        build_electra_historical_summaries_proof, build_historical_roots_proof, BlockHeaderProof,
        HeaderWithProof,
    },
    BlockBody,
};

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

pub fn decode_transactions(transactions: &Transactions) -> anyhow::Result<Vec<TxEnvelope>> {
    transactions
        .into_par_iter()
        .map(|raw_tx| {
            TxEnvelope::decode(&mut &**raw_tx)
                .map_err(|err| anyhow::anyhow!("Failed decoding transaction rlp: {err:?}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()
}
