use crate::types::{
    accumulator::EpochAccumulator,
    block_body::BlockBody,
    block_header::{BlockHeader, BlockHeaderWithProof},
    receipts::BlockReceipts,
};
use serde::{Deserialize, Serialize};

/// Portal History content items.
/// Supports both BlockHeaderWithProof and the depreciated BlockHeader content types
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HistoryContentItem {
    BlockHeaderWithProof(Box<BlockHeaderWithProof>),
    BlockHeader(Box<BlockHeader>),
    BlockBody(BlockBody),
    Receipts(BlockReceipts),
    EpochAccumulator(EpochAccumulator),
}
