use revm::context::DBErrorMarker;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EVMError {
    #[error("trie error {0}")]
    Trie(#[from] eth_trie::TrieError),

    #[error("rlp error {0}")]
    RLP(#[from] alloy::rlp::Error),

    #[error("rocksdb error {0}")]
    DB(#[from] rocksdb::Error),

    #[error("ethportal error {0}")]
    ANYHOW(#[from] anyhow::Error),

    #[error("not found database error {0}")]
    NotFound(String),

    #[error("balance error")]
    BalanceError,
}

impl DBErrorMarker for EVMError {}
