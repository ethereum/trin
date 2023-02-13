use crate::types::{
    accumulator::EpochAccumulator, block_body::BlockBody, block_header::BlockHeaderWithProof,
    receipts::BlockReceipts,
};
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};

/// Portal History content items.
/// Supports both BlockHeaderWithProof and the depreciated BlockHeader content types
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HistoryContentItem {
    BlockHeaderWithProof(Box<BlockHeaderWithProof>),
    BlockBody(BlockBody),
    Receipts(BlockReceipts),
    EpochAccumulator(EpochAccumulator),
    Unknown(String),
}

impl From<HistoryContentItem> for Vec<u8> {
    fn from(value: HistoryContentItem) -> Self {
        match value {
            HistoryContentItem::BlockHeaderWithProof(header_with_proof) => {
                header_with_proof.as_ssz_bytes()
            }
            HistoryContentItem::BlockBody(block_body) => block_body.as_ssz_bytes(),
            HistoryContentItem::Receipts(receipts) => receipts.as_ssz_bytes(),
            HistoryContentItem::EpochAccumulator(epoch_accumulator) => {
                epoch_accumulator.as_ssz_bytes()
            }
            HistoryContentItem::Unknown(hex_value) => hex_value.into_bytes(),
        }
    }
}

impl From<Vec<u8>> for HistoryContentItem {
    fn from(value: Vec<u8>) -> Self {
        match BlockHeaderWithProof::from_ssz_bytes(&value) {
            Ok(header_with_proof) => {
                HistoryContentItem::BlockHeaderWithProof(Box::from(header_with_proof))
            }
            Err(_) => match BlockBody::from_ssz_bytes(&value) {
                Ok(block_body) => HistoryContentItem::BlockBody(block_body),
                Err(_) => match BlockReceipts::from_ssz_bytes(&value) {
                    Ok(receipts) => HistoryContentItem::Receipts(receipts),
                    Err(_) => match EpochAccumulator::from_ssz_bytes(&value) {
                        Ok(epoch_accumulator) => {
                            HistoryContentItem::EpochAccumulator(epoch_accumulator)
                        }
                        Err(_) => HistoryContentItem::Unknown(hex::encode(value)),
                    },
                },
            },
        }
    }
}
