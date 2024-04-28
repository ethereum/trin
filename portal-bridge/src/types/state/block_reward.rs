use alloy_consensus::constants::ETH_TO_WEI;
use alloy_primitives::Address;
use ethportal_api::{BlockBody, BlockBodyLegacy};

use crate::types::era1::BlockTuple;

// Calculate block reward
// https://github.com/paradigmxyz/reth/blob/v0.2.0-beta.6/crates/consensus/common/src/calc.rs
pub fn get_block_reward(block_tuple: &BlockTuple) -> Vec<(Address, u128)> {
    let mut beneficiaries = vec![];
    let base_block_reward = ETH_TO_WEI * 5;

    if let BlockBody::Legacy(BlockBodyLegacy { uncles, .. }) = &block_tuple.body.body {
        for uncle in uncles.iter() {
            beneficiaries.push((
                uncle.author,
                ((8 + uncle.number - block_tuple.header.header.number) as u128 * base_block_reward)
                    >> 3,
            ));
        }

        beneficiaries.push((
            block_tuple.header.header.author,
            base_block_reward + (base_block_reward >> 5) * uncles.len() as u128,
        ));
    }

    beneficiaries
}
