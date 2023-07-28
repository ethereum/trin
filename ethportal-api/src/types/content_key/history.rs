use ethereum_types::H256;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as Sha2Digest, Sha256};
use ssz::{self, Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::fmt;

use crate::types::content_key::error::ContentKeyError;
use crate::types::content_key::overlay::OverlayContentKey;
use crate::utils::bytes::{hex_decode, hex_encode, hex_encode_compact};

/// SSZ encoded overlay content key as bytes
pub type RawContentKey = Vec<u8>;

/// A content key in the history overlay network.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[ssz(enum_behaviour = "union")]
pub enum HistoryContentKey {
    /// A block header with accumulator proof.
    BlockHeaderWithProof(BlockHeaderKey),
    /// A block body.
    BlockBody(BlockBodyKey),
    /// The transaction receipts for a block.
    BlockReceipts(BlockReceiptsKey),
    /// An epoch header accumulator.
    EpochAccumulator(EpochAccumulatorKey),
}

impl Serialize for HistoryContentKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for HistoryContentKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data = String::deserialize(deserializer)?.to_lowercase();

        if !data.starts_with("0x") {
            return Err(de::Error::custom(format!(
                "Hex strings must start with 0x, but found {}",
                &data[..2]
            )));
        }

        let ssz_bytes = hex_decode(&data).map_err(de::Error::custom)?;

        HistoryContentKey::from_ssz_bytes(&ssz_bytes)
            .map_err(|e| ContentKeyError::DecodeSsz {
                decode_error: e,
                input: hex_encode(ssz_bytes),
            })
            .map_err(serde::de::Error::custom)
    }
}

/// A key for a block header.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct BlockHeaderKey {
    /// Hash of the block.
    pub block_hash: [u8; 32],
}

/// A key for a block body.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct BlockBodyKey {
    /// Chain identifier.
    /// Hash of the block.
    pub block_hash: [u8; 32],
}

/// A key for the transaction receipts for a block.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct BlockReceiptsKey {
    /// Chain identifier.
    /// Hash of the block.
    pub block_hash: [u8; 32],
}

/// A key for an epoch header accumulator.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct EpochAccumulatorKey {
    pub epoch_hash: H256,
}

impl From<&HistoryContentKey> for Vec<u8> {
    fn from(val: &HistoryContentKey) -> Self {
        val.as_ssz_bytes()
    }
}

impl From<HistoryContentKey> for Vec<u8> {
    fn from(val: HistoryContentKey) -> Self {
        val.as_ssz_bytes()
    }
}

impl TryFrom<Vec<u8>> for HistoryContentKey {
    type Error = ContentKeyError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        HistoryContentKey::from_ssz_bytes(&value).map_err(|e| ContentKeyError::DecodeSsz {
            decode_error: e,
            input: hex_encode(value),
        })
    }
}

impl fmt::Display for HistoryContentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::BlockHeaderWithProof(header) => format!(
                "BlockHeaderWithProof {{ block_hash: {} }}",
                hex_encode_compact(header.block_hash)
            ),
            Self::BlockBody(body) => format!(
                "BlockBody {{ block_hash: {} }}",
                hex_encode_compact(body.block_hash)
            ),
            Self::BlockReceipts(receipts) => {
                format!(
                    "BlockReceipts {{ block_hash: {} }}",
                    hex_encode_compact(receipts.block_hash)
                )
            }
            Self::EpochAccumulator(acc) => {
                format!(
                    "EpochAccumulator {{ epoch_hash: {} }}",
                    hex_encode_compact(acc.epoch_hash.as_fixed_bytes())
                )
            }
        };

        write!(f, "{s}")
    }
}

impl OverlayContentKey for HistoryContentKey {
    fn content_id(&self) -> [u8; 32] {
        let mut sha256 = Sha256::new();
        sha256.update(self.as_ssz_bytes());
        sha256.finalize().into()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        match self {
            HistoryContentKey::BlockHeaderWithProof(k) => {
                bytes.push(0x00);
                bytes.extend_from_slice(&k.block_hash);
            }
            HistoryContentKey::BlockBody(k) => {
                bytes.push(0x01);
                bytes.extend_from_slice(&k.block_hash);
            }
            HistoryContentKey::BlockReceipts(k) => {
                bytes.push(0x02);
                bytes.extend_from_slice(&k.block_hash);
            }
            HistoryContentKey::EpochAccumulator(k) => {
                bytes.push(0x03);
                bytes.extend_from_slice(&k.epoch_hash.0);
            }
        }

        bytes
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use crate::types::content_key::overlay::OverlayContentKey;

    const BLOCK_HASH: [u8; 32] = [
        0xd1, 0xc3, 0x90, 0x62, 0x4d, 0x3b, 0xd4, 0xe4, 0x09, 0xa6, 0x1a, 0x85, 0x8e, 0x5d, 0xcc,
        0x55, 0x17, 0x72, 0x9a, 0x91, 0x70, 0xd0, 0x14, 0xa6, 0xc9, 0x65, 0x30, 0xd6, 0x4d, 0xd8,
        0x62, 0x1d,
    ];

    #[test]
    fn block_header() {
        const KEY_STR: &str =
            "0x00d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d";
        let expected_content_key = hex_decode(KEY_STR).unwrap();
        let expected_content_id: [u8; 32] = [
            0x3e, 0x86, 0xb3, 0x76, 0x7b, 0x57, 0x40, 0x2e, 0xa7, 0x2e, 0x36, 0x9a, 0xe0, 0x49,
            0x6c, 0xe4, 0x7c, 0xc1, 0x5b, 0xe6, 0x85, 0xbe, 0xc3, 0xb4, 0x72, 0x6b, 0x9f, 0x31,
            0x6e, 0x38, 0x95, 0xfe,
        ];

        let header = BlockHeaderKey {
            block_hash: BLOCK_HASH,
        };

        let key = HistoryContentKey::BlockHeaderWithProof(header);

        assert_eq!(key.to_bytes(), expected_content_key);
        assert_eq!(key.content_id(), expected_content_id);
        assert_eq!(
            key.to_string(),
            "BlockHeaderWithProof { block_hash: 0xd1c3..621d }"
        );
        assert_eq!(key.to_hex(), KEY_STR);
    }

    #[test]
    fn block_body() {
        const KEY_STR: &str =
            "0x01d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d";
        let expected_content_key = hex_decode(KEY_STR).unwrap();
        let expected_content_id: [u8; 32] = [
            0xeb, 0xe4, 0x14, 0x85, 0x46, 0x29, 0xd6, 0x0c, 0x58, 0xdd, 0xd5, 0xbf, 0x60, 0xfd,
            0x72, 0xe4, 0x17, 0x60, 0xa5, 0xf7, 0xa4, 0x63, 0xfd, 0xcb, 0x16, 0x9f, 0x13, 0xee,
            0x4a, 0x26, 0x78, 0x6b,
        ];

        let body = BlockBodyKey {
            block_hash: BLOCK_HASH,
        };

        let key = HistoryContentKey::BlockBody(body);

        assert_eq!(key.to_bytes(), expected_content_key);
        assert_eq!(key.content_id(), expected_content_id);
        assert_eq!(key.to_string(), "BlockBody { block_hash: 0xd1c3..621d }");
        assert_eq!(key.to_hex(), KEY_STR);
    }

    #[test]
    fn block_receipts() {
        const KEY_STR: &str =
            "0x02d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d";
        let expected_content_key = hex_decode(KEY_STR).unwrap();
        let expected_content_id: [u8; 32] = [
            0xa8, 0x88, 0xf4, 0xaa, 0xfe, 0x91, 0x09, 0xd4, 0x95, 0xac, 0x4d, 0x47, 0x74, 0xa6,
            0x27, 0x7c, 0x1a, 0xda, 0x42, 0x03, 0x5e, 0x3d, 0xa5, 0xe1, 0x0a, 0x04, 0xcc, 0x93,
            0x24, 0x7c, 0x04, 0xa4,
        ];

        let receipts = BlockReceiptsKey {
            block_hash: BLOCK_HASH,
        };

        let key = HistoryContentKey::BlockReceipts(receipts);

        assert_eq!(key.to_bytes(), expected_content_key);
        assert_eq!(key.content_id(), expected_content_id);
        assert_eq!(
            key.to_string(),
            "BlockReceipts { block_hash: 0xd1c3..621d }"
        );
        assert_eq!(key.to_hex(), KEY_STR);
    }

    // test values sourced from: https://github.com/ethereum/portal-network-specs/blob/master/content-keys-test-vectors.md
    #[test]
    fn epoch_accumulator_key() {
        let epoch_hash =
            hex_decode("0xe242814b90ed3950e13aac7e56ce116540c71b41d1516605aada26c6c07cc491")
                .unwrap();
        const KEY_STR: &str =
            "0x03e242814b90ed3950e13aac7e56ce116540c71b41d1516605aada26c6c07cc491";
        let expected_content_key = hex_decode(KEY_STR).unwrap();
        let expected_content_id =
            hex_decode("0x9fb2175e76c6989e0fdac3ee10c40d2a81eb176af32e1c16193e3904fe56896e")
                .unwrap();

        let key = HistoryContentKey::EpochAccumulator(EpochAccumulatorKey {
            epoch_hash: H256::from_slice(&epoch_hash),
        });

        // round trip
        let decoded = HistoryContentKey::try_from(key.to_bytes().to_vec()).unwrap();
        assert_eq!(decoded, key);

        assert_eq!(key.to_bytes(), expected_content_key);
        assert_eq!(key.content_id(), expected_content_id.as_ref());
        assert_eq!(
            key.to_string(),
            "EpochAccumulator { epoch_hash: 0xe242..c491 }"
        );
        assert_eq!(key.to_hex(), KEY_STR);
    }

    #[test]
    fn ser_de_block_header() {
        let content_key_json =
            "\"0x00d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d\"";
        let expected_content_key = HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey {
            block_hash: BLOCK_HASH,
        });

        let content_key: HistoryContentKey = serde_json::from_str(content_key_json).unwrap();

        assert_eq!(content_key, expected_content_key);
        assert_eq!(
            serde_json::to_string(&content_key).unwrap(),
            content_key_json
        );
    }

    #[test]
    fn ser_de_block_body_failure_prints_debuggable_data() {
        let content_key_json = "\"0x0123456789\"";
        let content_key_result = serde_json::from_str::<HistoryContentKey>(content_key_json);
        // Test the error Display representation
        assert_eq!(
            content_key_result.as_ref().unwrap_err().to_string(),
            "unable to decode key SSZ bytes 0x0123456789 due to InvalidByteLength { len: 4, expected: 32 }"
        );
    }

    #[test]
    fn ser_de_block_body() {
        let content_key_json =
            "\"0x01d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d\"";
        let expected_content_key = HistoryContentKey::BlockBody(BlockBodyKey {
            block_hash: BLOCK_HASH,
        });

        let content_key: HistoryContentKey = serde_json::from_str(content_key_json).unwrap();

        assert_eq!(content_key, expected_content_key);
        assert_eq!(
            serde_json::to_string(&content_key).unwrap(),
            content_key_json
        );
    }

    #[test]
    fn ser_de_block_receipts() {
        let content_key_json =
            "\"0x02d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d\"";
        let expected_content_key = HistoryContentKey::BlockReceipts(BlockReceiptsKey {
            block_hash: BLOCK_HASH,
        });

        let content_key: HistoryContentKey = serde_json::from_str(content_key_json).unwrap();

        assert_eq!(content_key, expected_content_key);
        assert_eq!(
            serde_json::to_string(&content_key).unwrap(),
            content_key_json
        );
    }

    #[test]
    fn ser_de_epoch_accumulator() {
        let content_key_json =
            "\"0x03e242814b90ed3950e13aac7e56ce116540c71b41d1516605aada26c6c07cc491\"";
        let epoch_hash =
            hex_decode("0xe242814b90ed3950e13aac7e56ce116540c71b41d1516605aada26c6c07cc491")
                .unwrap();
        let expected_content_key = HistoryContentKey::EpochAccumulator(EpochAccumulatorKey {
            epoch_hash: H256::from_slice(&epoch_hash),
        });

        let content_key: HistoryContentKey = serde_json::from_str(content_key_json).unwrap();

        assert_eq!(content_key, expected_content_key);
        assert_eq!(
            serde_json::to_string(&content_key).unwrap(),
            content_key_json
        );
    }
}
