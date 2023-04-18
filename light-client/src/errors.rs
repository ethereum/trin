use crate::types::BlockTag;
use eyre::Report;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("block not available: {block}")]
pub struct BlockNotFoundError {
    block: BlockTag,
}

impl BlockNotFoundError {
    pub fn new(block: BlockTag) -> Self {
        Self { block }
    }
}

#[derive(Debug, Error)]
#[error("rpc error on method: {method}, message: {error}")]
pub struct RpcError<E: ToString> {
    method: String,
    error: E,
}

impl<E: ToString> RpcError<E> {
    pub fn new(method: &str, err: E) -> Self {
        Self {
            method: method.to_string(),
            error: err,
        }
    }
}

/// Errors that can occur during Node calls
#[derive(Debug, Error)]
pub enum NodeError {
    #[error("out of sync: {0} slots behind")]
    OutOfSync(u64),

    #[error("consensus payload error: {0}")]
    ConsensusPayloadError(Report),

    #[error("consensus client creation error: {0}")]
    ConsensusClientCreationError(Report),

    #[error("consensus advance error: {0}")]
    ConsensusAdvanceError(Report),

    #[error("consensus sync error: {0}")]
    ConsensusSyncError(Report),

    #[error(transparent)]
    BlockNotFoundError(#[from] BlockNotFoundError),
}
