use db::{AsyncDatabaseRef, WrapAsyncDatabaseRef};
use ethportal_api::Header;
use revm_primitives::{EVMError, EVMResult, Env, SpecId, U256};
use tokio::{runtime, task};

use crate::{spec_id::get_spec_id, transaction::TxEnvModifier};

pub mod blocking;
pub mod db;

/// Creates the EVM environment for a given block header.
pub fn create_evm_environment(header: &Header) -> Env {
    let mut env = Env::default();

    let block = &mut env.block;
    block.number = U256::from(header.number);
    block.coinbase = header.author;
    block.timestamp = U256::from(header.timestamp);
    if get_spec_id(header.number).is_enabled_in(SpecId::MERGE) {
        block.difficulty = U256::ZERO;
        block.prevrandao = header.mix_hash;
    } else {
        block.difficulty = header.difficulty;
        block.prevrandao = None;
    }

    block.gas_limit = header.gas_limit;
    block.basefee = header.base_fee_per_gas.unwrap_or_default();

    // EIP-4844 excess blob gas of this block, introduced in Cancun
    if let Some(excess_blob_gas) = header.excess_blob_gas {
        block.set_blob_excess_gas_and_price(excess_blob_gas.to());
    }
    env
}

/// Executes the transaction.
///
/// It will spawn blocking thread and execute the transaction in a blocking way on it.
/// For executing transactions in a blocking manner, see "blocking" module.
pub async fn execute_transaction<'a, DB, E, T>(tx: T, evm_environment: Env, db: DB) -> EVMResult<E>
where
    DB: AsyncDatabaseRef<Error = E> + Send + 'static,
    E: Send + 'static,
    T: TxEnvModifier + Send + 'static,
{
    task::spawn_blocking(move || {
        let rt = runtime::Runtime::new().expect("to create Runtime within spawn_blocking");
        let database = WrapAsyncDatabaseRef::new(db, rt);
        blocking::execute_transaction(&tx, evm_environment, database)
    })
    .await
    .unwrap_or_else(|err| {
        Err(EVMError::Custom(format!(
            "Error while executing transactions asynchronously: {err:?}"
        )))
    })
}
