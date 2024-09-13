use std::future::Future;

use revm::Database;
use revm_primitives::{AccountInfo, Address, BlockEnv, Bytecode, EVMError, EVMResult, B256, U256};
use tokio::{runtime, task};

use super::{create_evm, tx_env_modifier::TxEnvModifier};

/// The async version of the [revm::Database].
pub trait AsyncDatabase {
    /// The database error type.
    type Error;

    /// Get basic account information.
    fn basic_async(
        &mut self,
        address: Address,
    ) -> impl Future<Output = Result<Option<AccountInfo>, Self::Error>> + Send;

    /// Get account code by its hash.
    fn code_by_hash_async(
        &mut self,
        code_hash: B256,
    ) -> impl Future<Output = Result<Bytecode, Self::Error>> + Send;

    /// Get storage value of address at index.
    fn storage_async(
        &mut self,
        address: Address,
        index: U256,
    ) -> impl Future<Output = Result<U256, Self::Error>> + Send;

    /// Get block hash by block number.
    fn block_hash_async(
        &mut self,
        number: u64,
    ) -> impl Future<Output = Result<B256, Self::Error>> + Send;
}

/// Wraps the [AsyncDatabase] to provide [revm::Database] implementation.
///
/// This should only be used when blocking thread is allowed, e.g. from within spawn::blocking.
pub struct WrapAsyncDatabase<DB: AsyncDatabase> {
    db: DB,
    rt: runtime::Runtime,
}

impl<DB: AsyncDatabase> WrapAsyncDatabase<DB> {
    pub fn new(db: DB, rt: runtime::Runtime) -> Self {
        Self { db, rt }
    }
}

impl<DB: AsyncDatabase> Database for WrapAsyncDatabase<DB> {
    type Error = DB::Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.rt.block_on(self.db.basic_async(address))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.rt.block_on(self.db.code_by_hash_async(code_hash))
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.rt.block_on(self.db.storage_async(address, index))
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.rt.block_on(self.db.block_hash_async(number))
    }
}

pub async fn execute_transaction<DB, DBError, Tx>(
    block_env: BlockEnv,
    tx: Tx,
    db: DB,
) -> EVMResult<DB::Error>
where
    DB: AsyncDatabase<Error = DBError> + Send + 'static,
    DBError: Send + 'static,
    Tx: TxEnvModifier + Send + 'static,
{
    task::spawn_blocking(move || {
        let rt = runtime::Runtime::new().expect("to create Runtime within spawn_blocking");
        let mut db = WrapAsyncDatabase::new(db, rt);
        let mut evm = create_evm(block_env, &tx, &mut db);
        evm.transact()
    })
    .await
    .unwrap_or_else(|err| {
        Err(EVMError::Custom(format!(
            "Error while executing transactions asynchronously: {err:?}"
        )))
    })
}
