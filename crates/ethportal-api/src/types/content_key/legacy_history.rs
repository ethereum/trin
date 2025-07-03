use std::{fmt, hash::Hash};

use bytes::{BufMut, BytesMut};
use rand::{rng, seq::IndexedRandom, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};

use crate::{
    types::content_key::{error::ContentKeyError, overlay::OverlayContentKey},
    utils::bytes::hex_encode_compact,
    RawContentKey,
};

// Prefixes for the different types of history content keys:
// https://github.com/ethereum/portal-network-specs/blob/638aca50c913a749d0d762264d9a4ac72f1a9966/history-network.md
pub const HISTORY_BLOCK_HEADER_BY_HASH_KEY_PREFIX: u8 = 0x00;
pub const HISTORY_BLOCK_BODY_KEY_PREFIX: u8 = 0x01;
pub const HISTORY_BLOCK_RECEIPTS_KEY_PREFIX: u8 = 0x02;
pub const HISTORY_BLOCK_HEADER_BY_NUMBER_KEY_PREFIX: u8 = 0x03;
pub const HISTORY_EPHEMERAL_HEADERS_FIND_CONTENT_KEY_PREFIX: u8 = 0x04;
pub const HISTORY_EPHEMERAL_HEADER_OFFER_KEY_PREFIX: u8 = 0x05;

/// A content key in the history overlay network.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LegacyHistoryContentKey {
    /// A block header by hash.
    BlockHeaderByHash(BlockHeaderByHashKey),
    /// A block header by number.
    BlockHeaderByNumber(BlockHeaderByNumberKey),
    /// A block body.
    BlockBody(BlockBodyKey),
    /// The transaction receipts for a block.
    BlockReceipts(BlockReceiptsKey),
    /// Ephemeral headers used for FindContent request.
    ///
    /// This is used to find the headers of a block and its ancestors.
    /// This content type can only be used by FindContent requests.
    EphemeralHeadersFindContent(EphemeralHeadersFindContentKey),
    /// Ephemeral header used for Offer request.
    ///
    /// This is used to offer an ephemeral block header to a peer. This content type can only be
    /// used by Offer requests. The type contains a single header, but more headers should be
    /// included in the single Offer request.
    EphemeralHeaderOffer(EphemeralHeaderOfferKey),
}

impl LegacyHistoryContentKey {
    pub fn random() -> anyhow::Result<Self> {
        let random_prefix = [
            HISTORY_BLOCK_HEADER_BY_HASH_KEY_PREFIX,
            HISTORY_BLOCK_BODY_KEY_PREFIX,
            HISTORY_BLOCK_RECEIPTS_KEY_PREFIX,
            HISTORY_BLOCK_HEADER_BY_NUMBER_KEY_PREFIX,
        ]
        .choose(&mut rng())
        .ok_or_else(|| anyhow::Error::msg("Failed to choose random prefix"))?;
        let mut random_bytes: Vec<u8> =
            if *random_prefix == HISTORY_BLOCK_HEADER_BY_NUMBER_KEY_PREFIX {
                vec![0u8; 8]
            } else {
                vec![0u8; 32]
            };
        rng().fill_bytes(&mut random_bytes[..]);
        random_bytes.insert(0, *random_prefix);
        Self::try_from_bytes(&random_bytes).map_err(anyhow::Error::msg)
    }

    pub fn new_block_header_by_hash(block_hash: impl Into<[u8; 32]>) -> Self {
        Self::BlockHeaderByHash(BlockHeaderByHashKey {
            block_hash: block_hash.into(),
        })
    }

    pub fn new_block_header_by_number(block_number: u64) -> Self {
        Self::BlockHeaderByNumber(BlockHeaderByNumberKey { block_number })
    }

    pub fn new_block_body(block_hash: impl Into<[u8; 32]>) -> Self {
        Self::BlockBody(BlockBodyKey {
            block_hash: block_hash.into(),
        })
    }

    pub fn new_block_receipts(block_hash: impl Into<[u8; 32]>) -> Self {
        Self::BlockReceipts(BlockReceiptsKey {
            block_hash: block_hash.into(),
        })
    }

    pub fn new_ephemeral_headers_find_content(
        block_hash: impl Into<[u8; 32]>,
        ancestor_count: u8,
    ) -> Self {
        Self::EphemeralHeadersFindContent(EphemeralHeadersFindContentKey {
            block_hash: block_hash.into(),
            ancestor_count,
        })
    }

    pub fn new_ephemeral_header_offer(block_hash: impl Into<[u8; 32]>) -> Self {
        Self::EphemeralHeaderOffer(EphemeralHeaderOfferKey {
            block_hash: block_hash.into(),
        })
    }
}

impl Hash for LegacyHistoryContentKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&self.to_bytes());
    }
}

impl Serialize for LegacyHistoryContentKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for LegacyHistoryContentKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = RawContentKey::deserialize(deserializer)?;
        Self::try_from_bytes(bytes).map_err(serde::de::Error::custom)
    }
}

/// A key for a block header by hash.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, Default)]
pub struct BlockHeaderByHashKey {
    /// Hash of the block.
    pub block_hash: [u8; 32],
}

/// A key for a block header by number.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, Default)]
pub struct BlockHeaderByNumberKey {
    /// Number of the block.
    pub block_number: u64,
}

/// A key for a block body.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct BlockBodyKey {
    /// Hash of the block.
    pub block_hash: [u8; 32],
}

/// A key for the transaction receipts for a block.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct BlockReceiptsKey {
    /// Hash of the block.
    pub block_hash: [u8; 32],
}

#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct EphemeralHeadersFindContentKey {
    /// Hash of the block.
    pub block_hash: [u8; 32],
    /// The number of ancestors included in the response.
    pub ancestor_count: u8,
}

/// A key for a block header by hash.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, Default)]
pub struct EphemeralHeaderOfferKey {
    /// Hash of the block.
    pub block_hash: [u8; 32],
}

impl fmt::Display for LegacyHistoryContentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::BlockHeaderByHash(header) => format!(
                "BlockHeaderByHash {{ block_hash: {} }}",
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
            Self::BlockHeaderByNumber(header) => {
                format!(
                    "BlockHeaderByNumber {{ block_number: {} }}",
                    header.block_number
                )
            }
            Self::EphemeralHeadersFindContent(ephemeral_headers) => {
                format!(
                    "EphemeralHeadersFindContent {{ block_hash: {}, ancestor_count: {} }}",
                    hex_encode_compact(ephemeral_headers.block_hash),
                    ephemeral_headers.ancestor_count
                )
            }
            Self::EphemeralHeaderOffer(ephemeral_header) => {
                format!(
                    "EphemeralHeaderOffer {{ block_hash: {} }}",
                    hex_encode_compact(ephemeral_header.block_hash),
                )
            }
        };

        write!(f, "{s}")
    }
}

impl OverlayContentKey for LegacyHistoryContentKey {
    fn affected_by_radius(&self) -> bool {
        match self {
            Self::BlockHeaderByHash(_) => true,
            Self::BlockHeaderByNumber(_) => true,
            Self::BlockBody(_) => true,
            Self::BlockReceipts(_) => true,
            Self::EphemeralHeadersFindContent(_) => false,
            Self::EphemeralHeaderOffer(_) => false,
        }
    }

    fn to_bytes(&self) -> RawContentKey {
        let mut bytes;

        match self {
            LegacyHistoryContentKey::BlockHeaderByHash(key) => {
                bytes = BytesMut::with_capacity(1 + key.ssz_bytes_len());
                bytes.put_u8(HISTORY_BLOCK_HEADER_BY_HASH_KEY_PREFIX);
                bytes.put_slice(&key.as_ssz_bytes());
            }
            LegacyHistoryContentKey::BlockBody(key) => {
                bytes = BytesMut::with_capacity(1 + key.ssz_bytes_len());
                bytes.put_u8(HISTORY_BLOCK_BODY_KEY_PREFIX);
                bytes.put_slice(&key.as_ssz_bytes());
            }
            LegacyHistoryContentKey::BlockReceipts(key) => {
                bytes = BytesMut::with_capacity(1 + key.ssz_bytes_len());
                bytes.put_u8(HISTORY_BLOCK_RECEIPTS_KEY_PREFIX);
                bytes.put_slice(&key.as_ssz_bytes());
            }
            LegacyHistoryContentKey::BlockHeaderByNumber(key) => {
                bytes = BytesMut::with_capacity(1 + key.ssz_bytes_len());
                bytes.put_u8(HISTORY_BLOCK_HEADER_BY_NUMBER_KEY_PREFIX);
                bytes.put_slice(&key.as_ssz_bytes());
            }
            LegacyHistoryContentKey::EphemeralHeadersFindContent(key) => {
                bytes = BytesMut::with_capacity(1 + key.ssz_bytes_len());
                bytes.put_u8(HISTORY_EPHEMERAL_HEADERS_FIND_CONTENT_KEY_PREFIX);
                bytes.put_slice(&key.as_ssz_bytes());
            }
            LegacyHistoryContentKey::EphemeralHeaderOffer(key) => {
                bytes = BytesMut::with_capacity(1 + key.ssz_bytes_len());
                bytes.put_u8(HISTORY_EPHEMERAL_HEADER_OFFER_KEY_PREFIX);
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
            HISTORY_BLOCK_HEADER_BY_HASH_KEY_PREFIX => BlockHeaderByHashKey::from_ssz_bytes(key)
                .map(Self::BlockHeaderByHash)
                .map_err(|e| ContentKeyError::from_decode_error(e, bytes)),
            HISTORY_BLOCK_BODY_KEY_PREFIX => BlockBodyKey::from_ssz_bytes(key)
                .map(Self::BlockBody)
                .map_err(|e| ContentKeyError::from_decode_error(e, bytes)),
            HISTORY_BLOCK_RECEIPTS_KEY_PREFIX => BlockReceiptsKey::from_ssz_bytes(key)
                .map(Self::BlockReceipts)
                .map_err(|e| ContentKeyError::from_decode_error(e, bytes)),
            HISTORY_BLOCK_HEADER_BY_NUMBER_KEY_PREFIX => {
                BlockHeaderByNumberKey::from_ssz_bytes(key)
                    .map(Self::BlockHeaderByNumber)
                    .map_err(|e| ContentKeyError::from_decode_error(e, bytes))
            }
            HISTORY_EPHEMERAL_HEADERS_FIND_CONTENT_KEY_PREFIX => {
                EphemeralHeadersFindContentKey::from_ssz_bytes(key)
                    .map(Self::EphemeralHeadersFindContent)
                    .map_err(|e| ContentKeyError::from_decode_error(e, bytes))
            }
            HISTORY_EPHEMERAL_HEADER_OFFER_KEY_PREFIX => {
                EphemeralHeaderOfferKey::from_ssz_bytes(key)
                    .map(Self::EphemeralHeaderOffer)
                    .map_err(|e| ContentKeyError::from_decode_error(e, bytes))
            }
            _ => Err(ContentKeyError::from_decode_error(
                DecodeError::UnionSelectorInvalid(selector),
                bytes,
            )),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use alloy::primitives::b256;

    use super::*;
    use crate::{types::content_key::overlay::OverlayContentKey, utils::bytes::hex_decode};

    const BLOCK_HASH: [u8; 32] = [
        0xd1, 0xc3, 0x90, 0x62, 0x4d, 0x3b, 0xd4, 0xe4, 0x09, 0xa6, 0x1a, 0x85, 0x8e, 0x5d, 0xcc,
        0x55, 0x17, 0x72, 0x9a, 0x91, 0x70, 0xd0, 0x14, 0xa6, 0xc9, 0x65, 0x30, 0xd6, 0x4d, 0xd8,
        0x62, 0x1d,
    ];

    #[test]
    fn block_header_by_hash() {
        const KEY_STR: &str =
            "0x00d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d";
        let expected_content_key = hex_decode(KEY_STR).unwrap();
        let expected_content_id: [u8; 32] = [
            0x3e, 0x86, 0xb3, 0x76, 0x7b, 0x57, 0x40, 0x2e, 0xa7, 0x2e, 0x36, 0x9a, 0xe0, 0x49,
            0x6c, 0xe4, 0x7c, 0xc1, 0x5b, 0xe6, 0x85, 0xbe, 0xc3, 0xb4, 0x72, 0x6b, 0x9f, 0x31,
            0x6e, 0x38, 0x95, 0xfe,
        ];

        let header = BlockHeaderByHashKey {
            block_hash: BLOCK_HASH,
        };

        let key = LegacyHistoryContentKey::BlockHeaderByHash(header);

        assert_eq!(key.to_bytes(), expected_content_key);
        assert_eq!(key.content_id(), expected_content_id);
        assert_eq!(
            key.to_string(),
            "BlockHeaderByHash { block_hash: 0xd1c3..621d }"
        );
        assert_eq!(key.to_hex(), KEY_STR);
    }

    #[test]
    fn block_header_by_number() {
        const BLOCK_NUMBER: u64 = 12345678;
        const KEY_STR: &str = "0x034e61bc0000000000";
        let expected_content_key = hex_decode(KEY_STR).unwrap();
        let expected_content_id: [u8; 32] =
            hex_decode("0x2113990747a85ab39785d21342fa5db1f68acc0011605c0c73f68fc331643dcf")
                .unwrap()
                .try_into()
                .unwrap();

        let header = BlockHeaderByNumberKey {
            block_number: BLOCK_NUMBER,
        };

        let key = LegacyHistoryContentKey::BlockHeaderByNumber(header);

        // round trip
        let decoded = LegacyHistoryContentKey::try_from_bytes(key.to_bytes()).unwrap();
        assert_eq!(decoded, key);

        assert_eq!(key.to_bytes(), expected_content_key);
        assert_eq!(key.content_id(), expected_content_id);
        assert_eq!(
            key.to_string(),
            "BlockHeaderByNumber { block_number: 12345678 }"
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

        let key = LegacyHistoryContentKey::BlockBody(body);

        // round trip
        let decoded = LegacyHistoryContentKey::try_from_bytes(key.to_bytes()).unwrap();
        assert_eq!(decoded, key);

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

        let key = LegacyHistoryContentKey::BlockReceipts(receipts);

        assert_eq!(key.to_bytes(), expected_content_key);
        assert_eq!(key.content_id(), expected_content_id);
        assert_eq!(
            key.to_string(),
            "BlockReceipts { block_hash: 0xd1c3..621d }"
        );
        assert_eq!(key.to_hex(), KEY_STR);
    }

    #[test]
    fn ser_de_block_header_by_hash() {
        let content_key_json =
            "\"0x00d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d\"";
        let expected_content_key =
            LegacyHistoryContentKey::BlockHeaderByHash(BlockHeaderByHashKey {
                block_hash: BLOCK_HASH,
            });

        let content_key: LegacyHistoryContentKey = serde_json::from_str(content_key_json).unwrap();

        assert_eq!(content_key, expected_content_key);
        assert_eq!(
            serde_json::to_string(&content_key).unwrap(),
            content_key_json
        );
    }

    #[test]
    fn ser_de_block_header_by_number() {
        let content_key_json = "\"0x034e61bc0000000000\"";
        let expected_content_key =
            LegacyHistoryContentKey::BlockHeaderByNumber(BlockHeaderByNumberKey {
                block_number: 12345678,
            });

        let content_key: LegacyHistoryContentKey = serde_json::from_str(content_key_json).unwrap();

        assert_eq!(content_key, expected_content_key);
        assert_eq!(
            serde_json::to_string(&content_key).unwrap(),
            content_key_json
        );
    }

    #[test]
    fn ser_de_block_body_failure_prints_debuggable_data() {
        let content_key_json = "\"0x0123456789\"";
        let content_key_result = serde_json::from_str::<LegacyHistoryContentKey>(content_key_json);
        // Test the error Display representation
        assert_eq!(
            content_key_result.as_ref().unwrap_err().to_string(),
            "Unable to decode key SSZ bytes 0x0123456789 due to InvalidByteLength { len: 4, expected: 32 }"
        );
    }

    #[test]
    fn ser_de_block_body() {
        let content_key_json =
            "\"0x01d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d\"";
        let expected_content_key = LegacyHistoryContentKey::new_block_body(BLOCK_HASH);

        let content_key: LegacyHistoryContentKey = serde_json::from_str(content_key_json).unwrap();

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
        let expected_content_key = LegacyHistoryContentKey::new_block_receipts(BLOCK_HASH);

        let content_key: LegacyHistoryContentKey = serde_json::from_str(content_key_json).unwrap();

        assert_eq!(content_key, expected_content_key);
        assert_eq!(
            serde_json::to_string(&content_key).unwrap(),
            content_key_json
        );
    }

    #[test]
    fn serde_ephemeral_headers_find_content() {
        let content_key_json =
            "\"0x04d24fd73f794058a3807db926d8898c6481e902b7edb91ce0d479d6760f27618301\"";
        let block_hash = b256!("d24fd73f794058a3807db926d8898c6481e902b7edb91ce0d479d6760f276183");
        let ancestor_count = 1;
        let expected_content_key =
            LegacyHistoryContentKey::new_ephemeral_headers_find_content(block_hash, ancestor_count);

        let content_key: LegacyHistoryContentKey = serde_json::from_str(content_key_json).unwrap();

        assert_eq!(content_key, expected_content_key);
        assert_eq!(
            serde_json::to_string(&content_key).unwrap(),
            content_key_json
        );
    }

    #[test]
    fn ephemeral_headers_find_content_content_id_derivations() {
        let block_hash = b256!("d24fd73f794058a3807db926d8898c6481e902b7edb91ce0d479d6760f276183");
        let ancestor_count = 1;
        let content_key =
            LegacyHistoryContentKey::new_ephemeral_headers_find_content(block_hash, ancestor_count);
        assert_eq!(
            **content_key.to_bytes(),
            hex_decode("0x04d24fd73f794058a3807db926d8898c6481e902b7edb91ce0d479d6760f27618301")
                .unwrap()
        );
        assert_eq!(
            content_key.content_id(),
            b256!("0xbf9f37c72f6635bbe8dbb4d9377a56d8d579a434399f4c5ba4aad5a213ca04d8")
        );
    }

    #[test]
    fn serde_ephemeral_header_offer() {
        let content_key_json =
            "\"0x05d24fd73f794058a3807db926d8898c6481e902b7edb91ce0d479d6760f276183\"";
        let block_hash = b256!("d24fd73f794058a3807db926d8898c6481e902b7edb91ce0d479d6760f276183");
        let expected_content_key = LegacyHistoryContentKey::new_ephemeral_header_offer(block_hash);

        let content_key: LegacyHistoryContentKey = serde_json::from_str(content_key_json).unwrap();

        assert_eq!(content_key, expected_content_key);
        assert_eq!(
            serde_json::to_string(&content_key).unwrap(),
            content_key_json
        );
    }

    #[test]
    fn ephemeral_header_offer_content_id_derivations() {
        let block_hash = b256!("d24fd73f794058a3807db926d8898c6481e902b7edb91ce0d479d6760f276183");
        let content_key = LegacyHistoryContentKey::new_ephemeral_header_offer(block_hash);
        assert_eq!(
            **content_key.to_bytes(),
            hex_decode("0x05d24fd73f794058a3807db926d8898c6481e902b7edb91ce0d479d6760f276183")
                .unwrap()
        );
        assert_eq!(
            content_key.content_id(),
            b256!("0x76744a5338183a04ea39bbb94906e539b9a839b4aa508f8493b2afbba2491567")
        );
    }
}
