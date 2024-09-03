use std::future::Future;

use revm::DatabaseRef;
use revm_primitives::{AccountInfo, Address, Bytecode, B256, U256};
use tokio::runtime;

/// The async version of the [DatabaseRef].
pub trait AsyncDatabaseRef {
    /// The database error type.
    type Error;

    /// Get basic account information.
    fn basic_async(
        &self,
        address: Address,
    ) -> impl Future<Output = Result<Option<AccountInfo>, Self::Error>> + Send;

    /// Get account code by its hash.
    fn code_by_hash_async(
        &self,
        code_hash: B256,
    ) -> impl Future<Output = Result<Bytecode, Self::Error>> + Send;

    /// Get storage value of address at index.
    fn storage_async(
        &self,
        address: Address,
        index: U256,
    ) -> impl Future<Output = Result<U256, Self::Error>> + Send;

    /// Get block hash by block number.
    fn block_hash_async(
        &self,
        number: U256,
    ) -> impl Future<Output = Result<B256, Self::Error>> + Send;
}

/// Wraps the [AsyncDatabaseRef] to provide [DatabaseRef] implementation.
///
/// This should only be used when blocking thread is allowed, e.g. from within spawn::blocking.
pub(super) struct WrapAsyncDatabaseRef<DB: AsyncDatabaseRef> {
    db: DB,
    rt: runtime::Runtime,
}

impl<DB: AsyncDatabaseRef> WrapAsyncDatabaseRef<DB> {
    pub fn new(db: DB, rt: runtime::Runtime) -> Self {
        Self { db, rt }
    }
}

impl<DB: AsyncDatabaseRef> DatabaseRef for WrapAsyncDatabaseRef<DB> {
    type Error = DB::Error;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.rt.block_on(self.db.basic_async(address))
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.rt.block_on(self.db.code_by_hash_async(code_hash))
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.rt.block_on(self.db.storage_async(address, index))
    }

    fn block_hash_ref(&self, number: U256) -> Result<B256, Self::Error> {
        self.rt.block_on(self.db.block_hash_async(number))
    }
}
