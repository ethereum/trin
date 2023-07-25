use crate::types::content_key::error::ContentKeyError;
use crate::types::content_key::overlay::OverlayContentKey;
use crate::utils::bytes::{hex_decode, hex_encode, hex_encode_compact};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::fmt;

/// A content key in the beacon chain network.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[ssz(enum_behaviour = "union")]
pub enum BeaconContentKey {
    LightClientBootstrap(LightClientBootstrapKey),
    LightClientUpdates(LightClientUpdatesKey),
}

/// Key used to identify a light client bootstrap.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct LightClientBootstrapKey {
    /// Hash of the block.
    pub block_hash: [u8; 32],
}

/// Key used to identify a set of light client updates.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct LightClientUpdatesKey {
    /// The start sync committee period.
    pub start_period: u64,
    /// the count of periods.
    pub count: u64,
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
            Self::LightClientUpdates(key) => format!(
                "LightClientUpdates {{ start_period: {}, count: {} }}",
                key.start_period, key.count
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
                bytes.push(0x00);
                bytes.extend_from_slice(&key.block_hash);
            }
            BeaconContentKey::LightClientUpdates(key) => {
                bytes.push(0x01);
                bytes.extend_from_slice(&key.start_period.to_le_bytes());
                bytes.extend_from_slice(&key.count.to_le_bytes());
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

    #[test]
    fn light_client_bootstrap() {
        // Slot 6718368
        const KEY_STR: &str =
            "0x00bd9f42d9a42d972bdaf4dee84e5b419dd432b52867258acb7bcc7f567b6e3af1";
        const BLOCK_HASH: &str =
            "0xbd9f42d9a42d972bdaf4dee84e5b419dd432b52867258acb7bcc7f567b6e3af1";

        let expected_content_key = hex_decode(KEY_STR).unwrap();

        let bootstrap = LightClientBootstrapKey {
            block_hash: <[u8; 32]>::try_from(hex_decode(BLOCK_HASH).unwrap()).unwrap(),
        };

        let key = BeaconContentKey::LightClientBootstrap(bootstrap);

        assert_eq!(key.to_bytes(), expected_content_key);
        assert_eq!(
            key.to_string(),
            "LightClientBootstrap { block_hash: 0xbd9f..3af1 }"
        );
        assert_eq!(key.to_hex(), KEY_STR);
    }
}
