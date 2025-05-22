// todo: remove once ephemeral history bridge is added
#![allow(dead_code)]

use ethportal_api::{consensus::beacon_block::BeaconBlockElectra, BlockBody, Receipts};
use revm_primitives::B256;

pub struct EphemeralBundle {
    pub head_block_root: B256,
    /// Used to generate header series
    pub beacon_blocks: Vec<BeaconBlockElectra>,
    pub bodies: Vec<(B256, BlockBody)>,
    pub receipts: Vec<(B256, Receipts)>,
}

impl EphemeralBundle {
    pub fn new(head_block_root: B256) -> Self {
        Self {
            head_block_root,
            beacon_blocks: vec![],
            bodies: vec![],
            receipts: vec![],
        }
    }

    pub fn push_beacon_block(&mut self, beacon_block: BeaconBlockElectra) {
        self.beacon_blocks.push(beacon_block);
    }

    pub fn push_body(&mut self, block_hash: B256, body: BlockBody) {
        self.bodies.push((block_hash, body));
    }

    pub fn push_receipts(&mut self, block_hash: B256, receipts: Receipts) {
        self.receipts.push((block_hash, receipts));
    }
}
