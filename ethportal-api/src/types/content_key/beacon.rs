use crate::{
    types::content_key::{error::ContentKeyError, overlay::OverlayContentKey},
    utils::bytes::{hex_decode, hex_encode, hex_encode_compact},
};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use std::fmt;

// Prefixes for the different types of beacon content keys:
// https://github.com/ethereum/portal-network-specs/blob/72327da43c7a199ba2735344ef98f9121aef2f68/beacon-chain/beacon-network.md
pub const LIGHT_CLIENT_BOOTSTRAP_KEY_PREFIX: u8 = 0x10;
pub const LIGHT_CLIENT_UPDATES_BY_RANGE_KEY_PREFIX: u8 = 0x11;
pub const LIGHT_CLIENT_FINALITY_UPDATE_KEY_PREFIX: u8 = 0x12;
pub const LIGHT_CLIENT_OPTIMISTIC_UPDATE_KEY_PREFIX: u8 = 0x13;

/// A content key in the beacon chain network.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BeaconContentKey {
    LightClientBootstrap(LightClientBootstrapKey),
    LightClientUpdatesByRange(LightClientUpdatesByRangeKey),
    LightClientFinalityUpdate(LightClientFinalityUpdateKey),
    LightClientOptimisticUpdate(LightClientOptimisticUpdateKey),
}

impl Encode for BeaconContentKey {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let bytes = self.to_bytes();
        buf.extend_from_slice(&bytes);
    }

    fn ssz_bytes_len(&self) -> usize {
        self.to_bytes().len()
    }
}

impl Decode for BeaconContentKey {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        match bytes[0] {
            LIGHT_CLIENT_BOOTSTRAP_KEY_PREFIX => {
                let block_hash = <[u8; 32]>::try_from(&bytes[1..33]).map_err(|err| {
                    DecodeError::BytesInvalid(format!(
                        "Failed to decode LightClientBootstrapKey: {err:?}"
                    ))
                })?;
                Ok(Self::LightClientBootstrap(LightClientBootstrapKey {
                    block_hash,
                }))
            }
            LIGHT_CLIENT_UPDATES_BY_RANGE_KEY_PREFIX => {
                let start_period = u64::from_ssz_bytes(&bytes[1..9]).map_err(|err| {
                    DecodeError::BytesInvalid(format!(
                        "Failed to decode LightClientUpdatesByRangeKey: {err:?}"
                    ))
                })?;
                let count = u64::from_ssz_bytes(&bytes[9..17]).map_err(|err| {
                    DecodeError::BytesInvalid(format!(
                        "Failed to decode LightClientUpdatesByRangeKey: {err:?}"
                    ))
                })?;
                Ok(Self::LightClientUpdatesByRange(
                    LightClientUpdatesByRangeKey {
                        start_period,
                        count,
                    },
                ))
            }
            LIGHT_CLIENT_FINALITY_UPDATE_KEY_PREFIX => {
                let finalized_slot = u64::from_ssz_bytes(&bytes[1..9]).map_err(|err| {
                    DecodeError::BytesInvalid(format!(
                        "Failed to decode LightClientFinalityUpdateKey: {err:?}",
                    ))
                })?;
                Ok(Self::LightClientFinalityUpdate(
                    LightClientFinalityUpdateKey::new(finalized_slot),
                ))
            }
            LIGHT_CLIENT_OPTIMISTIC_UPDATE_KEY_PREFIX => {
                let signature_slot = u64::from_ssz_bytes(&bytes[1..9]).map_err(|err| {
                    DecodeError::BytesInvalid(format!(
                        "Failed to decode LightClientOptimisticUpdateKey: {err:?}",
                    ))
                })?;
                Ok(Self::LightClientOptimisticUpdate(
                    LightClientOptimisticUpdateKey::new(signature_slot),
                ))
            }
            _ => Err(DecodeError::BytesInvalid(format!(
                "Failed to decode BeaconContentKey, Unexpected union selector byte: {bytes:?}",
            ))),
        }
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

impl From<&BeaconContentKey> for Vec<u8> {
    fn from(val: &BeaconContentKey) -> Self {
        val.as_ssz_bytes()
    }
}

impl From<BeaconContentKey> for Vec<u8> {
    fn from(val: BeaconContentKey) -> Self {
        val.as_ssz_bytes()
    }
}

impl TryFrom<Vec<u8>> for BeaconContentKey {
    type Error = ContentKeyError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        BeaconContentKey::from_ssz_bytes(&value).map_err(|e| ContentKeyError::DecodeSsz {
            decode_error: e,
            input: hex_encode(value),
        })
    }
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
        };

        write!(f, "{s}")
    }
}

impl OverlayContentKey for BeaconContentKey {
    fn content_id(&self) -> [u8; 32] {
        let mut sha256 = Sha256::new();
        sha256.update(self.as_ssz_bytes());
        sha256.finalize().into()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        match self {
            BeaconContentKey::LightClientBootstrap(key) => {
                bytes.push(LIGHT_CLIENT_BOOTSTRAP_KEY_PREFIX);
                bytes.extend_from_slice(&key.block_hash);
            }
            BeaconContentKey::LightClientUpdatesByRange(key) => {
                bytes.push(LIGHT_CLIENT_UPDATES_BY_RANGE_KEY_PREFIX);
                bytes.extend_from_slice(&key.start_period.as_ssz_bytes());
                bytes.extend_from_slice(&key.count.as_ssz_bytes());
            }
            BeaconContentKey::LightClientFinalityUpdate(key) => {
                bytes.push(LIGHT_CLIENT_FINALITY_UPDATE_KEY_PREFIX);
                bytes.extend_from_slice(&key.finalized_slot.as_ssz_bytes())
            }
            BeaconContentKey::LightClientOptimisticUpdate(key) => {
                bytes.push(LIGHT_CLIENT_OPTIMISTIC_UPDATE_KEY_PREFIX);
                bytes.extend_from_slice(&key.signature_slot.as_ssz_bytes())
            }
        }

        bytes
    }
}

impl Serialize for BeaconContentKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for BeaconContentKey {
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

        Self::from_ssz_bytes(&ssz_bytes)
            .map_err(|e| ContentKeyError::DecodeSsz {
                decode_error: e,
                input: hex_encode(ssz_bytes),
            })
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;

    fn test_ssz_encode_decode(content_key: &BeaconContentKey) {
        let ssz_bytes = content_key.as_ssz_bytes();
        let decoded_key = BeaconContentKey::from_ssz_bytes(&ssz_bytes).unwrap();
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

        test_ssz_encode_decode(&content_key);

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

        test_ssz_encode_decode(&content_key);

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

        test_ssz_encode_decode(&content_key);

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

        test_ssz_encode_decode(&content_key);

        assert_eq!(content_key.to_bytes(), expected_content_key);
        assert_eq!(
            content_key.to_string(),
            "LightClientOptimisticUpdate { signature_slot: 7271362 }"
        );
        assert_eq!(content_key.to_hex(), KEY_STR);
    }
}
