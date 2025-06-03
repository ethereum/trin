use revm::context::DBErrorMarker;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EVMError {
    #[error("trie error {0}")]
    Trie(#[from] eth_trie::TrieError),

    #[error("rlp error {0}")]
    RLP(#[from] alloy::rlp::Error),

    #[error("redb error {0}")]
    DB(#[from] Box<redb::Error>),

    #[error("ethportal error {0}")]
    ANYHOW(#[from] anyhow::Error),

    #[error("not found database error {0}")]
    NotFound(String),

    #[error("balance error")]
    BalanceError,
}

impl DBErrorMarker for EVMError {}

impl From<redb::DatabaseError> for EVMError {
    fn from(err: redb::DatabaseError) -> Self {
        EVMError::ANYHOW(anyhow::anyhow!("redb database error: {}", err))
    }
}

impl From<redb::TransactionError> for EVMError {
    fn from(err: redb::TransactionError) -> Self {
        EVMError::ANYHOW(anyhow::anyhow!("redb transaction error: {}", err))
    }
}

impl From<redb::TableError> for EVMError {
    fn from(err: redb::TableError) -> Self {
        EVMError::ANYHOW(anyhow::anyhow!("redb table error: {}", err))
    }
}

impl From<redb::StorageError> for EVMError {
    fn from(err: redb::StorageError) -> Self {
        EVMError::ANYHOW(anyhow::anyhow!("redb storage error: {}", err))
    }
}

impl From<redb::CommitError> for EVMError {
    fn from(err: redb::CommitError) -> Self {
        EVMError::ANYHOW(anyhow::anyhow!("redb commit error: {}", err))
    }
}
