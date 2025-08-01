use std::{fmt, hash::Hash};

use bytes::{BufMut, BytesMut};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};

use crate::{
    types::content_key::content_id::range_content_id, ContentKeyError, OverlayContentKey,
    RawContentKey,
};

// Prefixes for the different types of history content keys
pub const HISTORY_BLOCK_BODY_KEY_PREFIX: u8 = 0x00;
pub const HISTORY_BLOCK_RECEIPTS_KEY_PREFIX: u8 = 0x01;

/// A content key used in Portal History network
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HistoryContentKey {
    /// A block body.
    BlockBody(BlockBodyKey),
    /// The transaction receipts for a block.
    BlockReceipts(BlockReceiptsKey),
}

/// A key for a block body.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct BlockBodyKey {
    /// The block number.
    pub block_number: u64,
}

/// A key for the transaction receipts for a block.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct BlockReceiptsKey {
    /// The block number.
    pub block_number: u64,
}

impl HistoryContentKey {
    pub fn new_block_body(block_number: u64) -> Self {
        Self::BlockBody(BlockBodyKey { block_number })
    }

    pub fn new_block_receipts(block_number: u64) -> Self {
        Self::BlockReceipts(BlockReceiptsKey { block_number })
    }
}

impl OverlayContentKey for HistoryContentKey {
    fn content_id(&self) -> [u8; 32] {
        match self {
            HistoryContentKey::BlockBody(key) => {
                range_content_id(key.block_number, HISTORY_BLOCK_BODY_KEY_PREFIX)
            }
            HistoryContentKey::BlockReceipts(key) => {
                range_content_id(key.block_number, HISTORY_BLOCK_RECEIPTS_KEY_PREFIX)
            }
        }
    }

    fn affected_by_radius(&self) -> bool {
        true
    }

    fn to_bytes(&self) -> RawContentKey {
        let mut bytes;

        match self {
            Self::BlockBody(key) => {
                bytes = BytesMut::with_capacity(1 + key.ssz_bytes_len());
                bytes.put_u8(HISTORY_BLOCK_BODY_KEY_PREFIX);
                bytes.put_slice(&key.as_ssz_bytes());
            }
            Self::BlockReceipts(key) => {
                bytes = BytesMut::with_capacity(1 + key.ssz_bytes_len());
                bytes.put_u8(HISTORY_BLOCK_RECEIPTS_KEY_PREFIX);
                bytes.put_slice(&key.as_ssz_bytes());
            }
        }

        RawContentKey::from(bytes.freeze())
    }

    fn try_from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, ContentKeyError> {
        let bytes = bytes.as_ref();
        let Some((&selector, key)) = bytes.split_first() else {
            return Err(ContentKeyError::InvalidLength {
                received: bytes.len(),
                expected: 1,
            });
        };
        match selector {
            HISTORY_BLOCK_BODY_KEY_PREFIX => BlockBodyKey::from_ssz_bytes(key)
                .map(Self::BlockBody)
                .map_err(|e| ContentKeyError::from_decode_error(e, bytes)),
            HISTORY_BLOCK_RECEIPTS_KEY_PREFIX => BlockReceiptsKey::from_ssz_bytes(key)
                .map(Self::BlockReceipts)
                .map_err(|e| ContentKeyError::from_decode_error(e, bytes)),
            _ => Err(ContentKeyError::from_decode_error(
                DecodeError::UnionSelectorInvalid(selector),
                bytes,
            )),
        }
    }
}

impl fmt::Display for HistoryContentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlockBody(body) => {
                write!(f, "BlockBody({})", body.block_number)
            }
            Self::BlockReceipts(receipts) => {
                write!(f, "BlockReceipts({})", receipts.block_number)
            }
        }
    }
}

impl Hash for HistoryContentKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&self.to_bytes());
    }
}

impl Serialize for HistoryContentKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for HistoryContentKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = RawContentKey::deserialize(deserializer)?;
        Self::try_from_bytes(bytes).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{b256, bytes, B256};
    use rstest::rstest;

    use super::*;

    mod content_id {
        use super::*;

        #[rstest]
        #[case::block_number_0(0, B256::with_last_byte(HISTORY_BLOCK_BODY_KEY_PREFIX))]
        #[case::block_number_12_345_678(12_345_678, b256!("0x614e3d0000000000000000000000000000000000000000000000000000000000"))]
        fn block_body(#[case] block_number: u64, #[case] expected_content_id: B256) {
            let content_key = HistoryContentKey::new_block_body(block_number);
            assert_eq!(content_key.content_id(), expected_content_id);
        }

        #[rstest]
        #[case::block_number_0(0, B256::with_last_byte(HISTORY_BLOCK_RECEIPTS_KEY_PREFIX))]
        #[case::block_number_12_345_678(12_345_678, b256!("0x614e3d0000000000000000000000000000000000000000000000000000000001"))]
        fn block_receipts(#[case] block_number: u64, #[case] expected_content_id: B256) {
            let content_key = HistoryContentKey::new_block_receipts(block_number);
            assert_eq!(content_key.content_id(), expected_content_id);
        }
    }
    mod to_from_bytes {
        use super::*;

        #[rstest]
        #[case::block_number_0(0, bytes!("0x000000000000000000"))]
        #[case::block_number_12_345_678(12_345_678, bytes!("0x004e61bc0000000000"))]
        fn block_body(#[case] block_number: u64, #[case] content_key_bytes: RawContentKey) {
            let content_key = HistoryContentKey::new_block_body(block_number);

            assert_eq!(content_key.to_bytes(), content_key_bytes);
            assert_eq!(
                HistoryContentKey::try_from_bytes(&content_key_bytes),
                Ok(content_key)
            );
        }

        #[rstest]
        #[case::block_number_0(0, bytes!("0x010000000000000000"))]
        #[case::block_number_12_345_678(12_345_678, bytes!("0x014e61bc0000000000"))]
        fn block_receipts(#[case] block_number: u64, #[case] content_key_bytes: RawContentKey) {
            let content_key = HistoryContentKey::new_block_receipts(block_number);

            assert_eq!(content_key.to_bytes(), content_key_bytes);
            assert_eq!(
                HistoryContentKey::try_from_bytes(&content_key_bytes),
                Ok(content_key)
            );
        }
    }
}
