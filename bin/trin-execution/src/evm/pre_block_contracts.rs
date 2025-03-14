use alloy::{consensus::Header, eips::eip4788};
use anyhow::anyhow;
use revm::{db::State, DatabaseCommit, Evm};
use revm_primitives::{SpecId, TxEnv, TxKind, U256};
use trin_evm::spec_id::get_spec_id;

use crate::storage::evm_db::EvmDB;

/// Apply the beacon roots contract from eip-4788
fn apply_beacon_root_contract(
    evm: &mut Evm<(), State<EvmDB>>,
    header: &Header,
) -> anyhow::Result<()> {
    if !get_spec_id(header.number).is_enabled_in(SpecId::CANCUN) {
        return Ok(());
    }

    let Some(parent_beacon_block_root) = header.parent_beacon_block_root else {
        return Err(anyhow!("Parent beacon block root is missing"));
    };

    // Save the previous environment
    let previous_env = Box::new(evm.context.evm.env().clone());

    // Update transaction environment to call the beacon roots contract
    evm.context.evm.env.tx = TxEnv {
        caller: eip4788::SYSTEM_ADDRESS,
        transact_to: TxKind::Call(eip4788::BEACON_ROOTS_ADDRESS),
        data: parent_beacon_block_root.0.into(),
        ..Default::default()
    };
    evm.context.evm.env.block.gas_limit = U256::from(evm.context.evm.env.tx.gas_limit);
    evm.context.evm.env.block.basefee = U256::ZERO;

    let mut state = match evm.transact() {
        Ok(result) => result.state,
        Err(err) => return Err(anyhow!("Failed to call beacon roots contract: {err:?}")),
    };

    // Remove all the keys except the beacon roots address which is the only state change we want to
    // keep
    state.retain(|address, _| address == &eip4788::BEACON_ROOTS_ADDRESS);

    evm.context.evm.db.commit(state);

    // Restore the previous environment
    evm.context.evm.env = previous_env;

    Ok(())
}

/// Apply pre-block contracts
pub fn apply_pre_block_contracts(
    evm: &mut Evm<(), State<EvmDB>>,
    header: &Header,
) -> anyhow::Result<()> {
    apply_beacon_root_contract(evm, header)?;
    Ok(())
}
