use crate::types::{
    accumulator::EpochAccumulator,
    block_body::BlockBody,
    block_header::{BlockHeader, BlockHeaderWithProof},
    receipts::BlockReceipts,
};
use serde::{Deserialize, Serialize};
use ssz::Encode;

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

impl From<HistoryContentItem> for Vec<u8> {
    fn from(value: HistoryContentItem) -> Self {
        match value {
            HistoryContentItem::BlockHeaderWithProof(header_with_proof) => {
                header_with_proof.as_ssz_bytes()
            }
            HistoryContentItem::BlockHeader(header) => rlp::encode(&header.0).to_vec(),
            HistoryContentItem::BlockBody(block_body) => block_body.as_ssz_bytes(),
            HistoryContentItem::Receipts(receipts) => receipts.as_ssz_bytes(),
            HistoryContentItem::EpochAccumulator(epoch_accumulator) => {
                epoch_accumulator.as_ssz_bytes()
            }
        }
    }
}
