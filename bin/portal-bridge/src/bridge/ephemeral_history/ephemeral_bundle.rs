// todo: remove once ephemeral history bridge is added
#![allow(dead_code)]

use alloy::{
    consensus::{BlockBody as AlloyBlockBody, Header},
    rpc::types::{Withdrawal, Withdrawals},
};
use anyhow::ensure;
use ethportal_api::{
    consensus::beacon_block::BeaconBlockElectra,
    types::execution::builders::{block::decode_transactions, header::ExecutionHeaderBuilder},
    BlockBody, Receipts,
};
use revm_primitives::B256;
use tree_hash::TreeHash;

pub struct EphemeralBundle {
    pub head_block_root: B256,
    pub blocks: Vec<(Header, BlockBody, Receipts)>,
}

impl EphemeralBundle {
    pub fn new(head_block_root: B256) -> Self {
        Self {
            head_block_root,
            blocks: vec![],
        }
    }

    fn next_parent_hash(&self) -> B256 {
        self.blocks
            .last()
            .map(|(header, ..)| header.parent_hash)
            .unwrap_or(self.head_block_root)
    }

    pub fn push_parent(
        &mut self,
        beacon_block: BeaconBlockElectra,
        receipts: Receipts,
    ) -> anyhow::Result<()> {
        ensure!(
            self.next_parent_hash() == beacon_block.tree_hash_root(),
            "Beacon block root does not match the expected parent hash"
        );
        let payload = &beacon_block.body.execution_payload;
        let transactions =
            decode_transactions(&payload.transactions).expect("Failed to decode transactions");
        let withdrawals = payload
            .withdrawals
            .iter()
            .map(Withdrawal::from)
            .collect::<Vec<_>>();
        let header = ExecutionHeaderBuilder::electra(
            payload,
            beacon_block.parent_root,
            &transactions,
            &withdrawals,
            &beacon_block.body.execution_requests,
        )
        .expect("Failed to build header");

        let block_body = BlockBody(AlloyBlockBody {
            transactions,
            ommers: vec![],
            withdrawals: Some(Withdrawals::new(withdrawals)),
        });

        self.blocks.push((header, block_body, receipts));

        Ok(())
    }
}
