use alloy::{
    consensus::{
        proofs::{calculate_transaction_root, calculate_withdrawals_root},
        BlockBody as AlloyBlockBody, Header, TxEnvelope,
    },
    eips::eip4895::{Withdrawal, Withdrawals},
    primitives::{Bloom, B256, B64, U256},
};
use anyhow::ensure;
use ethportal_api::{
    consensus::{
        beacon_block::{
            BeaconBlockBellatrix, BeaconBlockCapella, BeaconBlockDeneb, BeaconBlockElectra,
        },
        beacon_state::HistoricalBatch,
        execution_payload::{
            ExecutionPayloadBellatrix, ExecutionPayloadCapella, ExecutionPayloadDeneb,
            ExecutionPayloadElectra,
        },
        execution_requests::ExecutionRequests,
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
use trin_execution::era::beacon::{decode_transactions, EMPTY_UNCLE_ROOT_HASH};

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

pub fn deneb_execution_payload_to_header(
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

pub fn electra_execution_payload_to_header(
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
        requests_hash: Some(requests.requests_hash()),
    };

    ensure!(
        payload.block_hash == header.hash_slow(),
        "Block hash mismatch"
    );
    Ok(header)
}

pub fn get_merge_to_capella_header_and_body(
    block: &BeaconBlockBellatrix,
    historical_batch: &HistoricalBatch,
) -> anyhow::Result<(HeaderWithProof, BlockBody)> {
    let payload = &block.body.execution_payload;

    let transactions = decode_transactions(&payload.transactions)?;

    let header_with_proof = HeaderWithProof {
        header: bellatrix_execution_payload_to_header(payload, &transactions)?,
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

pub fn get_capella_to_deneb_header_and_body(
    block: &BeaconBlockCapella,
    historical_batch: &HistoricalBatch,
) -> anyhow::Result<(HeaderWithProof, BlockBody)> {
    let payload = &block.body.execution_payload;

    let transactions = decode_transactions(&payload.transactions)?;
    let withdrawals: Vec<Withdrawal> = payload.withdrawals.iter().map(Withdrawal::from).collect();

    let header_with_proof = HeaderWithProof {
        header: capella_execution_payload_to_header(payload, &transactions, &withdrawals)?,
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

pub fn get_deneb_to_electra_header_and_body(
    block: &BeaconBlockDeneb,
    historical_batch: &HistoricalBatch,
) -> anyhow::Result<(HeaderWithProof, BlockBody)> {
    let payload = &block.body.execution_payload;

    let transactions = decode_transactions(&payload.transactions)?;
    let withdrawals: Vec<Withdrawal> = payload.withdrawals.iter().map(Withdrawal::from).collect();

    let header_with_proof = HeaderWithProof {
        header: deneb_execution_payload_to_header(
            payload,
            block.parent_root,
            &transactions,
            &withdrawals,
        )?,
        proof: BlockHeaderProof::HistoricalSummariesDeneb(build_deneb_historical_summaries_proof(
            block.slot,
            &historical_batch.block_roots,
            block,
        )),
    };
    let body = BlockBody(AlloyBlockBody {
        transactions,
        ommers: vec![],
        withdrawals: Some(Withdrawals::new(withdrawals)),
    });

    Ok((header_with_proof, body))
}

pub fn get_post_electra_header_and_body(
    block: &BeaconBlockElectra,
    historical_batch: &HistoricalBatch,
) -> anyhow::Result<(HeaderWithProof, BlockBody)> {
    let payload = &block.body.execution_payload;

    let transactions = decode_transactions(&payload.transactions)?;
    let withdrawals: Vec<Withdrawal> = payload.withdrawals.iter().map(Withdrawal::from).collect();

    let header_with_proof = HeaderWithProof {
        header: electra_execution_payload_to_header(
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
