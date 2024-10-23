use crate::{
    types::content_key::{error::ContentKeyError, overlay::OverlayContentKey},
    utils::bytes::hex_encode_compact,
    RawContentKey,
};
use bytes::{BufMut, BytesMut};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use std::{fmt, hash::Hash};

// Prefixes for the different types of beacon content keys:
// https://github.com/ethereum/portal-network-specs/blob/638aca50c913a749d0d762264d9a4ac72f1a9966/beacon-chain/beacon-network.md
pub const LIGHT_CLIENT_BOOTSTRAP_KEY_PREFIX: u8 = 0x10;
pub const LIGHT_CLIENT_UPDATES_BY_RANGE_KEY_PREFIX: u8 = 0x11;
pub const LIGHT_CLIENT_FINALITY_UPDATE_KEY_PREFIX: u8 = 0x12;
pub const LIGHT_CLIENT_OPTIMISTIC_UPDATE_KEY_PREFIX: u8 = 0x13;
pub const HISTORICAL_SUMMARIES_WITH_PROOF_KEY_PREFIX: u8 = 0x14;

/// A content key in the beacon chain network.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BeaconContentKey {
    LightClientBootstrap(LightClientBootstrapKey),
    LightClientUpdatesByRange(LightClientUpdatesByRangeKey),
    LightClientFinalityUpdate(LightClientFinalityUpdateKey),
    LightClientOptimisticUpdate(LightClientOptimisticUpdateKey),
    HistoricalSummariesWithProof(HistoricalSummariesWithProofKey),
}

impl Hash for BeaconContentKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&self.to_bytes());
    }
}

/// Key used to identify a light client bootstrap.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct LightClientBootstrapKey {
    /// Hash of the block.
    pub block_hash: [u8; 32],
}

/// Key used to identify a set of light client updates.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct LightClientUpdatesByRangeKey {
    /// The start sync committee period.
    pub start_period: u64,
    /// the count of periods.
    pub count: u64,
}

/// Key used to identify a light client finality update.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct LightClientFinalityUpdateKey {
    /// Finalized slot number
    pub finalized_slot: u64,
}

impl LightClientFinalityUpdateKey {
    pub fn new(finalized_slot: u64) -> Self {
        Self { finalized_slot }
    }
}

/// Key used to identify a light client optimistic update.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct LightClientOptimisticUpdateKey {
    /// Signature slot number
    pub signature_slot: u64,
}

impl LightClientOptimisticUpdateKey {
    pub fn new(signature_slot: u64) -> Self {
        Self { signature_slot }
    }
}

/// Key used to identify a latest historical summaries with proof.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct HistoricalSummariesWithProofKey {
    /// Epoch of the historical summaries.
    pub epoch: u64,
}

impl fmt::Display for BeaconContentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::LightClientBootstrap(key) => format!(
                "LightClientBootstrap {{ block_hash: {} }}",
                hex_encode_compact(key.block_hash)
            ),
            Self::LightClientUpdatesByRange(key) => format!(
                "LightClientUpdatesByRange {{ start_period: {}, count: {} }}",
                key.start_period, key.count
            ),
            Self::LightClientFinalityUpdate(key) => format!(
                "LightClientFinalityUpdate {{ finalized_slot: {} }}",
                key.finalized_slot
            ),
            Self::LightClientOptimisticUpdate(key) => format!(
                "LightClientOptimisticUpdate {{ signature_slot: {} }}",
                key.signature_slot
            ),
            Self::HistoricalSummariesWithProof(key) => {
                format!("HistoricalSummariesWithProof {{ epoch: {} }}", key.epoch)
            }
        };

        write!(f, "{s}")
    }
}

impl OverlayContentKey for BeaconContentKey {
    fn to_bytes(&self) -> RawContentKey {
        let mut bytes;

        match self {
            BeaconContentKey::LightClientBootstrap(key) => {
                bytes = BytesMut::with_capacity(1 + key.ssz_bytes_len());
                bytes.put_u8(LIGHT_CLIENT_BOOTSTRAP_KEY_PREFIX);
                bytes.put_slice(&key.as_ssz_bytes());
            }
            BeaconContentKey::LightClientUpdatesByRange(key) => {
                bytes = BytesMut::with_capacity(1 + key.ssz_bytes_len());
                bytes.put_u8(LIGHT_CLIENT_UPDATES_BY_RANGE_KEY_PREFIX);
                bytes.put_slice(&key.as_ssz_bytes());
            }
            BeaconContentKey::LightClientFinalityUpdate(key) => {
                bytes = BytesMut::with_capacity(1 + key.ssz_bytes_len());
                bytes.put_u8(LIGHT_CLIENT_FINALITY_UPDATE_KEY_PREFIX);
                bytes.put_slice(&key.as_ssz_bytes());
            }
            BeaconContentKey::LightClientOptimisticUpdate(key) => {
                bytes = BytesMut::with_capacity(1 + key.ssz_bytes_len());
                bytes.put_u8(LIGHT_CLIENT_OPTIMISTIC_UPDATE_KEY_PREFIX);
                bytes.put_slice(&key.as_ssz_bytes());
            }
            BeaconContentKey::HistoricalSummariesWithProof(key) => {
                bytes = BytesMut::with_capacity(1 + key.ssz_bytes_len());
                bytes.put_u8(HISTORICAL_SUMMARIES_WITH_PROOF_KEY_PREFIX);
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
            LIGHT_CLIENT_BOOTSTRAP_KEY_PREFIX => LightClientBootstrapKey::from_ssz_bytes(key)
                .map(Self::LightClientBootstrap)
                .map_err(|e| ContentKeyError::from_decode_error(e, bytes)),
            LIGHT_CLIENT_UPDATES_BY_RANGE_KEY_PREFIX => {
                LightClientUpdatesByRangeKey::from_ssz_bytes(key)
                    .map(Self::LightClientUpdatesByRange)
                    .map_err(|e| ContentKeyError::from_decode_error(e, bytes))
            }
            LIGHT_CLIENT_FINALITY_UPDATE_KEY_PREFIX => {
                LightClientFinalityUpdateKey::from_ssz_bytes(key)
                    .map(Self::LightClientFinalityUpdate)
                    .map_err(|e| ContentKeyError::from_decode_error(e, bytes))
            }
            LIGHT_CLIENT_OPTIMISTIC_UPDATE_KEY_PREFIX => {
                LightClientOptimisticUpdateKey::from_ssz_bytes(key)
                    .map(Self::LightClientOptimisticUpdate)
                    .map_err(|e| ContentKeyError::from_decode_error(e, bytes))
            }
            HISTORICAL_SUMMARIES_WITH_PROOF_KEY_PREFIX => {
                HistoricalSummariesWithProofKey::from_ssz_bytes(key)
                    .map(Self::HistoricalSummariesWithProof)
                    .map_err(|e| ContentKeyError::from_decode_error(e, bytes))
            }
            _ => Err(ContentKeyError::from_decode_error(
                DecodeError::UnionSelectorInvalid(selector),
                bytes,
            )),
        }
    }
}

impl Serialize for BeaconContentKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BeaconContentKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = RawContentKey::deserialize(deserializer)?;
        Self::try_from_bytes(bytes).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use crate::utils::bytes::hex_decode;

    use super::*;

    fn test_encode_decode(content_key: &BeaconContentKey) {
        let bytes = content_key.to_bytes();
        let decoded_key = BeaconContentKey::try_from_bytes(bytes).unwrap();
        assert_eq!(*content_key, decoded_key);
    }

    #[test]
    fn light_client_bootstrap() {
        // Slot 6718368
        const KEY_STR: &str =
            "0x10bd9f42d9a42d972bdaf4dee84e5b419dd432b52867258acb7bcc7f567b6e3af1";
        const BLOCK_HASH: &str =
            "0xbd9f42d9a42d972bdaf4dee84e5b419dd432b52867258acb7bcc7f567b6e3af1";

        let expected_content_key = hex_decode(KEY_STR).unwrap();

        let bootstrap = LightClientBootstrapKey {
            block_hash: <[u8; 32]>::try_from(hex_decode(BLOCK_HASH).unwrap()).unwrap(),
        };

        let content_key = BeaconContentKey::LightClientBootstrap(bootstrap);

        test_encode_decode(&content_key);

        assert_eq!(content_key.to_bytes(), expected_content_key);
        assert_eq!(
            content_key.to_string(),
            "LightClientBootstrap { block_hash: 0xbd9f..3af1 }"
        );
        assert_eq!(content_key.to_hex(), KEY_STR);
    }

    #[test]
    fn light_client_updates_by_range() {
        const KEY_STR: &str = "0x1130030000000000000400000000000000";
        let expected_content_key = hex_decode(KEY_STR).unwrap();

        // SLOT / (SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD)
        let start_period: u64 = 6684738 / (32 * 256);

        let content_key = LightClientUpdatesByRangeKey {
            start_period,
            count: 4,
        };

        let content_key = BeaconContentKey::LightClientUpdatesByRange(content_key);

        test_encode_decode(&content_key);

        assert_eq!(content_key.to_bytes(), expected_content_key);
        assert_eq!(
            content_key.to_string(),
            "LightClientUpdatesByRange { start_period: 816, count: 4 }"
        );
        assert_eq!(content_key.to_hex(), KEY_STR);
    }

    #[test]
    fn light_client_finality_update() {
        const KEY_STR: &str = "0x12c2f36e0000000000";
        let expected_content_key = hex_decode(KEY_STR).unwrap();
        let content_key =
            BeaconContentKey::LightClientFinalityUpdate(LightClientFinalityUpdateKey::new(7271362));

        test_encode_decode(&content_key);

        assert_eq!(content_key.to_bytes(), expected_content_key);
        assert_eq!(
            content_key.to_string(),
            "LightClientFinalityUpdate { finalized_slot: 7271362 }"
        );
        assert_eq!(content_key.to_hex(), KEY_STR);
    }

    #[test]
    fn light_client_optimistic_update() {
        const KEY_STR: &str = "0x13c2f36e0000000000";
        let expected_content_key = hex_decode(KEY_STR).unwrap();
        let content_key = BeaconContentKey::LightClientOptimisticUpdate(
            LightClientOptimisticUpdateKey::new(7271362),
        );

        test_encode_decode(&content_key);

        assert_eq!(content_key.to_bytes(), expected_content_key);
        assert_eq!(
            content_key.to_string(),
            "LightClientOptimisticUpdate { signature_slot: 7271362 }"
        );
        assert_eq!(content_key.to_hex(), KEY_STR);
    }

    #[test]
    fn historical_summaries_with_proof() {
        const KEY_STR: &str = "0x14ae7e346485874006";
        let expected_content_key = hex_decode(KEY_STR).unwrap();
        let content_key =
            BeaconContentKey::HistoricalSummariesWithProof(HistoricalSummariesWithProofKey {
                epoch: 450508969718611630,
            });

        test_encode_decode(&content_key);

        assert_eq!(content_key.to_bytes(), expected_content_key);
        assert_eq!(
            content_key.to_string(),
            "HistoricalSummariesWithProof { epoch: 450508969718611630 }"
        );
        assert_eq!(content_key.to_hex(), KEY_STR);
    }
}
