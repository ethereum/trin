use alloy::{consensus::Header, eips::eip4788};
use anyhow::anyhow;
use revm::{
    context::{ContextTr, TxEnv},
    database::State,
    handler::MainnetContext,
    DatabaseCommit, ExecuteEvm, MainnetEvm,
};
use revm_primitives::{hardfork::SpecId, TxKind};
use trin_evm::spec_id::get_spec_id;

use crate::storage::evm_db::EvmDB;

/// Apply the beacon roots contract from eip-4788
fn apply_beacon_root_contract(
    evm: &mut MainnetEvm<MainnetContext<State<EvmDB>>, ()>,
    header: &Header,
) -> anyhow::Result<()> {
    if !get_spec_id(header.number).is_enabled_in(SpecId::CANCUN) {
        return Ok(());
    }

    let Some(parent_beacon_block_root) = header.parent_beacon_block_root else {
        return Err(anyhow!("Parent beacon block root is missing"));
    };

    // Save the previous environment
    let previous_block = evm.block.clone();
    let previous_cfg = evm.cfg.clone();
    let previous_transaction = evm.tx.clone();

    // Update transaction environment to call the beacon roots contract
    evm.tx = TxEnv {
        caller: eip4788::SYSTEM_ADDRESS,
        kind: TxKind::Call(eip4788::BEACON_ROOTS_ADDRESS),
        data: parent_beacon_block_root.0.into(),
        ..Default::default()
    };
    evm.block.gas_limit = evm.tx.gas_limit;
    evm.block.basefee = 0;

    let mut state = match evm.replay() {
        Ok(result) => result.state,
        Err(err) => return Err(anyhow!("Failed to call beacon roots contract: {err:?}")),
    };

    // Remove all the keys except the beacon roots address which is the only state change we want to
    // keep
    state.retain(|address, _| address == &eip4788::BEACON_ROOTS_ADDRESS);

    evm.db().commit(state);

    // Restore the previous environment
    evm.block = previous_block;
    evm.cfg = previous_cfg;
    evm.tx = previous_transaction;

    Ok(())
}

/// Apply pre-block contracts
pub fn apply_pre_block_contracts(
    evm: &mut MainnetEvm<MainnetContext<State<EvmDB>>, ()>,
    header: &Header,
) -> anyhow::Result<()> {
    apply_beacon_root_contract(evm, header)?;
    Ok(())
}
