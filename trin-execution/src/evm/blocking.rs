use revm::{
    db::WrapDatabaseRef, inspector_handle_register, inspectors::NoOpInspector, DatabaseRef, Evm,
    GetInspector,
};
use revm_primitives::{EVMResult, Env};

use crate::{spec_id::get_spec_id, transaction::TxEnvModifier};

/// Executes the transaction in the blocking manner.
pub fn execute_transaction<DB: DatabaseRef>(
    tx: &impl TxEnvModifier,
    evm_environment: Env,
    database: DB,
) -> EVMResult<DB::Error> {
    execute_transaction_with_external_context(tx, evm_environment, NoOpInspector, database)
}

/// Executes the transaction with external context in the blocking manner.
pub fn execute_transaction_with_external_context<
    DB: DatabaseRef,
    EXT: GetInspector<WrapDatabaseRef<DB>>,
>(
    tx: &impl TxEnvModifier,
    evm_environment: Env,
    external_context: EXT,
    database: DB,
) -> EVMResult<DB::Error> {
    let block_number = evm_environment.block.number.to::<u64>();
    Evm::builder()
        .with_ref_db(database)
        .with_env(Box::new(evm_environment))
        .with_spec_id(get_spec_id(block_number))
        .modify_tx_env(|tx_env| tx.modify(block_number, tx_env))
        .with_external_context(external_context)
        .append_handler_register(inspector_handle_register)
        .build()
        .transact()
}
