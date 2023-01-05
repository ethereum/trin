use ethereum_types::H256;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as Sha2Digest, Sha256};
use ssz::{self, Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::fmt;

/// Types whose values represent keys to lookup content items in an overlay network.
/// Keys are serializable.
pub trait OverlayContentKey:
    Into<Vec<u8>> + TryFrom<Vec<u8>> + Clone + fmt::Debug + fmt::Display
{
    /// Returns the identifier for the content referred to by the key.
    /// The identifier locates the content in the overlay.
    fn content_id(&self) -> [u8; 32];
}

/// A content key in the history overlay network.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[ssz(enum_behaviour = "union")]
pub enum HistoryContentKey {
    /// A block header with accumulator proof.
    BlockHeader(BlockHeaderKey),
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
        match self {
            HistoryContentKey::BlockHeader(block_header) => {
                let ssz_bytes = block_header.as_ssz_bytes();
                let hex_bytes = hex::encode(ssz_bytes);
                let selector = "00";
                serializer.serialize_str(&format!("0x{selector}{hex_bytes}"))
            }
            HistoryContentKey::BlockBody(block_body) => {
                let ssz_bytes = block_body.as_ssz_bytes();
                let hex_bytes = hex::encode(ssz_bytes);
                let selector = "01";
                serializer.serialize_str(&format!("0x{selector}{hex_bytes}"))
            }
            HistoryContentKey::BlockReceipts(block_receipt) => {
                let ssz_bytes = block_receipt.as_ssz_bytes();
                let hex_bytes = hex::encode(ssz_bytes);
                let selector = "02";
                serializer.serialize_str(&format!("0x{selector}{hex_bytes}"))
            }
            HistoryContentKey::EpochAccumulator(block_accumulator) => {
                let ssz_bytes = block_accumulator.as_ssz_bytes();
                let hex_bytes = hex::encode(ssz_bytes);
                let selector = "03";
                serializer.serialize_str(&format!("0x{selector}{hex_bytes}"))
            }
        }
    }
}

impl<'de> Deserialize<'de> for HistoryContentKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data = String::deserialize(deserializer)?.to_lowercase();
        let first_two = &data[..2];

        if first_two != "0x" {
            return Err(de::Error::custom(format!(
                "Hex strings must start with 0x, but found {first_two}"
            )));
        }

        let ssz_bytes = hex::decode(&data[2..]).map_err(de::Error::custom)?;

        match HistoryContentKey::from_ssz_bytes(&ssz_bytes) {
            Ok(content_key) => Ok(content_key),
            Err(_) => Err(de::Error::custom("Unable to deserialize from ssz bytes!")),
        }
    }
}

/// A key for a block header.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct BlockHeaderKey {
    /// Chain identifier.
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

// Silence clippy to avoid implementing newtype pattern on imported type.
#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for HistoryContentKey {
    fn into(self) -> Vec<u8> {
        self.as_ssz_bytes()
    }
}

impl TryFrom<Vec<u8>> for HistoryContentKey {
    type Error = &'static str;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        match HistoryContentKey::from_ssz_bytes(&value) {
            Ok(key) => Ok(key),
            Err(_err) => Err("Unable to decode SSZ"),
        }
    }
}

impl fmt::Display for HistoryContentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::BlockHeader(header) => format!(
                "BlockHeader {{ block_hash: {} }}",
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
}

/// Returns a compact hex-encoded `String` representation of `data`.
pub fn hex_encode_compact<T: AsRef<[u8]>>(data: T) -> String {
    if data.as_ref().len() <= 8 {
        format!("0x{}", hex::encode(data))
    } else {
        let hex = hex::encode(data);
        format!("0x{}..{}", &hex[0..4], &hex[hex.len() - 4..])
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use hex;

    //
    // History Network Content Key Tests
    //

    const BLOCK_HASH: [u8; 32] = [
        0xd1, 0xc3, 0x90, 0x62, 0x4d, 0x3b, 0xd4, 0xe4, 0x09, 0xa6, 0x1a, 0x85, 0x8e, 0x5d, 0xcc,
        0x55, 0x17, 0x72, 0x9a, 0x91, 0x70, 0xd0, 0x14, 0xa6, 0xc9, 0x65, 0x30, 0xd6, 0x4d, 0xd8,
        0x62, 0x1d,
    ];

    #[test]
    fn block_header() {
        let expected_content_key =
            hex::decode("00d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d")
                .unwrap();
        let expected_content_id: [u8; 32] = [
            0x3e, 0x86, 0xb3, 0x76, 0x7b, 0x57, 0x40, 0x2e, 0xa7, 0x2e, 0x36, 0x9a, 0xe0, 0x49,
            0x6c, 0xe4, 0x7c, 0xc1, 0x5b, 0xe6, 0x85, 0xbe, 0xc3, 0xb4, 0x72, 0x6b, 0x9f, 0x31,
            0x6e, 0x38, 0x95, 0xfe,
        ];

        let header = BlockHeaderKey {
            block_hash: BLOCK_HASH,
        };

        let key = HistoryContentKey::BlockHeader(header);
        let encoded: Vec<u8> = key.clone().into();

        assert_eq!(encoded, expected_content_key);
        assert_eq!(key.content_id(), expected_content_id);
    }

    #[test]
    fn block_body() {
        let expected_content_key =
            hex::decode("01d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d")
                .unwrap();
        let expected_content_id: [u8; 32] = [
            0xeb, 0xe4, 0x14, 0x85, 0x46, 0x29, 0xd6, 0x0c, 0x58, 0xdd, 0xd5, 0xbf, 0x60, 0xfd,
            0x72, 0xe4, 0x17, 0x60, 0xa5, 0xf7, 0xa4, 0x63, 0xfd, 0xcb, 0x16, 0x9f, 0x13, 0xee,
            0x4a, 0x26, 0x78, 0x6b,
        ];

        let body = BlockBodyKey {
            block_hash: BLOCK_HASH,
        };

        let key = HistoryContentKey::BlockBody(body);
        let encoded: Vec<u8> = key.clone().into();

        assert_eq!(encoded, expected_content_key);
        assert_eq!(key.content_id(), expected_content_id);
    }

    #[test]
    fn block_receipts() {
        let expected_content_key =
            hex::decode("02d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d")
                .unwrap();
        let expected_content_id: [u8; 32] = [
            0xa8, 0x88, 0xf4, 0xaa, 0xfe, 0x91, 0x09, 0xd4, 0x95, 0xac, 0x4d, 0x47, 0x74, 0xa6,
            0x27, 0x7c, 0x1a, 0xda, 0x42, 0x03, 0x5e, 0x3d, 0xa5, 0xe1, 0x0a, 0x04, 0xcc, 0x93,
            0x24, 0x7c, 0x04, 0xa4,
        ];

        let receipts = BlockReceiptsKey {
            block_hash: BLOCK_HASH,
        };

        let key = HistoryContentKey::BlockReceipts(receipts);
        let encoded: Vec<u8> = key.clone().into();

        assert_eq!(encoded, expected_content_key);
        assert_eq!(key.content_id(), expected_content_id);
    }

    // test values sourced from: https://github.com/ethereum/portal-network-specs/blob/master/content-keys-test-vectors.md
    #[test]
    fn epoch_accumulator_key() {
        let epoch_hash =
            hex::decode("e242814b90ed3950e13aac7e56ce116540c71b41d1516605aada26c6c07cc491")
                .unwrap();
        let expected_content_key_encoding =
            hex::decode("03e242814b90ed3950e13aac7e56ce116540c71b41d1516605aada26c6c07cc491")
                .unwrap();
        let expected_content_id =
            &hex::decode("9fb2175e76c6989e0fdac3ee10c40d2a81eb176af32e1c16193e3904fe56896e")
                .unwrap();

        let content_key = HistoryContentKey::EpochAccumulator(EpochAccumulatorKey {
            epoch_hash: H256::from_slice(&epoch_hash),
        });
        assert_eq!(&content_key.content_id().to_vec(), expected_content_id);

        let encoded_content_key: Vec<u8> = content_key.clone().into();
        assert_eq!(encoded_content_key, expected_content_key_encoding);

        // round trip
        let decoded = HistoryContentKey::try_from(encoded_content_key).unwrap();
        assert_eq!(decoded, content_key);
    }

    #[test]
    fn ser_de_block_header() {
        let content_key_json =
            "\"0x00d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d\"";
        let expected_content_key = HistoryContentKey::BlockHeader(BlockHeaderKey {
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
            hex::decode("e242814b90ed3950e13aac7e56ce116540c71b41d1516605aada26c6c07cc491")
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
