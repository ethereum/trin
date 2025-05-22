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

/// The container for Ephemeral headers to be gossiped together.
///
/// It's initialized with beacon block root of the head of the chain, and first added block must
/// correspond to it. Afterwards, each added block must be the parent of the previous. This
/// way, we create reverse chain of blocks.
pub struct EphemeralBundle {
    pub head_beacon_block_root: B256,
    pub blocks: Vec<(Header, BlockBody, Receipts)>,
}

impl EphemeralBundle {
    pub fn new(head_beacon_block_root: B256) -> Self {
        Self {
            head_beacon_block_root,
            blocks: vec![],
        }
    }

    pub fn next_parent_root(&self) -> B256 {
        self.blocks
            .last()
            .map(|(header, ..)| {
                header
                    .parent_beacon_block_root
                    .expect("This bridge only supports post Electra")
            })
            .unwrap_or(self.head_beacon_block_root)
    }

    pub fn push_parent(
        &mut self,
        beacon_block: BeaconBlockElectra,
        receipts: Receipts,
    ) -> anyhow::Result<()> {
        ensure!(
            self.next_parent_root() == beacon_block.tree_hash_root(),
            "Beacon block root does not match the expected parent root"
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
