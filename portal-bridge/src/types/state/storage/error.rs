use thiserror::Error;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum EVMError {
    #[error("trie error {0}")]
    Trie(#[from] eth_trie::TrieError),

    #[error("rlp error {0}")]
    RLP(#[from] alloy_rlp::Error),

    #[error("rocksdb error {0}")]
    DB(#[from] rocksdb::Error),

    #[error("not found")]
    NotFound,

    #[error("balance error")]
    BalanceError,
}
