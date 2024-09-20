use std::collections::HashMap;

use alloy_consensus::constants::ETH_TO_WEI;
use alloy_primitives::Address;
use revm::{db::State, Evm};
use revm_primitives::SpecId;
use trin_evm::spec_id::get_spec_block_number;

use crate::{era::types::ProcessedBlock, storage::evm_db::EvmDB};

use super::dao_fork::{DAO_HARDFORK_BENEFICIARY, DAO_HARDKFORK_ACCOUNTS};

// Calculate block reward
// https://github.com/paradigmxyz/reth/blob/v0.2.0-beta.6/crates/consensus/common/src/calc.rs
pub fn process_block_rewards(block: &ProcessedBlock, beneficiaries: &mut HashMap<Address, u128>) {
    let base_block_reward = if block.header.number >= get_spec_block_number(SpecId::MERGE) {
        // After the merge, the block reward is 0'
        // Validators are rewarded through the beacon chain
        return;
    } else if block.header.number >= get_spec_block_number(SpecId::CONSTANTINOPLE) {
        ETH_TO_WEI * 2
    } else if block.header.number >= get_spec_block_number(SpecId::BYZANTIUM) {
        ETH_TO_WEI * 3
    } else {
        ETH_TO_WEI * 5
    };

    if let Some(uncles) = &block.uncles {
        for uncle in uncles.iter() {
            *beneficiaries.entry(uncle.author).or_default() +=
                ((8 + uncle.number - block.header.number) as u128 * base_block_reward) >> 3;
        }

        *beneficiaries.entry(block.header.author).or_default() +=
            base_block_reward + (base_block_reward >> 5) * uncles.len() as u128;
    }
}

pub fn process_withdrawals(block: &ProcessedBlock, beneficiaries: &mut HashMap<Address, u128>) {
    if let Some(withdrawals) = &block.withdrawals {
        for withdrawal in withdrawals.iter() {
            if withdrawal.amount == 0 {
                continue;
            }
            *beneficiaries.entry(withdrawal.address).or_default() += withdrawal.amount as u128;
        }
    }
}

fn process_dao_fork(
    evm: &mut Evm<(), State<EvmDB>>,
    block: &ProcessedBlock,
    beneficiaries: &mut HashMap<Address, u128>,
) -> anyhow::Result<()> {
    if block.header.number == get_spec_block_number(SpecId::DAO_FORK) {
        // drain balances from DAO hardfork accounts
        let drained_balances = evm.db_mut().drain_balances(DAO_HARDKFORK_ACCOUNTS)?;
        let drained_balance_sum: u128 = drained_balances.iter().sum();

        // transfer drained balance to beneficiary
        *beneficiaries.entry(DAO_HARDFORK_BENEFICIARY).or_default() += drained_balance_sum;
    }

    Ok(())
}

pub fn get_post_block_beneficiaries(
    evm: &mut Evm<(), State<EvmDB>>,
    block: &ProcessedBlock,
) -> anyhow::Result<HashMap<Address, u128>> {
    let mut beneficiaries = HashMap::new();
    process_block_rewards(block, &mut beneficiaries);
    process_withdrawals(block, &mut beneficiaries);
    process_dao_fork(evm, block, &mut beneficiaries)?;
    Ok(beneficiaries)
}
