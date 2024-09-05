use alloy_consensus::constants::ETH_TO_WEI;
use alloy_primitives::Address;
use revm_primitives::SpecId;

use crate::{era::types::ProcessedBlock, spec_id::get_spec_block_number};

// Calculate block reward
// https://github.com/paradigmxyz/reth/blob/v0.2.0-beta.6/crates/consensus/common/src/calc.rs
pub fn get_block_reward(block: &ProcessedBlock) -> Vec<(Address, u128)> {
    let mut beneficiaries = vec![];

    let base_block_reward = if block.header.number >= get_spec_block_number(SpecId::MERGE) {
        0
    } else if block.header.number >= get_spec_block_number(SpecId::CONSTANTINOPLE) {
        ETH_TO_WEI * 2
    } else if block.header.number >= get_spec_block_number(SpecId::BYZANTIUM) {
        ETH_TO_WEI * 3
    } else {
        ETH_TO_WEI * 5
    };

    // If the block reward is 0, the Merge happened which means the execution layer no longer
    // determines the block reward
    if base_block_reward > 0 {
        if let Some(uncles) = &block.uncles {
            for uncle in uncles.iter() {
                beneficiaries.push((
                    uncle.author,
                    ((8 + uncle.number - block.header.number) as u128 * base_block_reward) >> 3,
                ));
            }

            beneficiaries.push((
                block.header.author,
                base_block_reward + (base_block_reward >> 5) * uncles.len() as u128,
            ));
        }
    }

    beneficiaries
}
