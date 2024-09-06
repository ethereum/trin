use revm::{inspector_handle_register, Database, Evm, GetInspector};
use revm_primitives::{EVMResult, Env};

use crate::spec_id::get_spec_id;

/// Executes the transaction with external context in the blocking manner.
pub fn execute_transaction_with_external_context<
    DB: Database,
    EXT: revm::Inspector<DB> + for<'a> GetInspector<&'a mut DB>,
>(
    evm_environment: Env,
    external_context: EXT,
    database: &mut DB,
) -> EVMResult<DB::Error> {
    let block_number = evm_environment.block.number.to::<u64>();
    Evm::builder()
        .with_env(Box::new(evm_environment))
        .with_spec_id(get_spec_id(block_number))
        .with_db(database)
        .with_external_context(external_context)
        .append_handler_register(inspector_handle_register)
        .build()
        .transact()
}
