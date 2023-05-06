use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::{Decode, Encode};

use trin_utils::bytes::{hex_decode, hex_encode};

/// Types based off specs @
/// https://github.com/ethereum/consensus-specs/blob/5970ae56a1/specs/phase0/beacon-chain.md
#[derive(Debug, PartialEq, Clone)]
pub struct PubKey([u8; 48]);

impl Decode for PubKey {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let mut key = [0u8; 48];
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }
    fn ssz_fixed_len() -> usize {
        48
    }
}

impl Encode for PubKey {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
    fn ssz_bytes_len(&self) -> usize {
        self.0.len()
    }
    fn ssz_fixed_len() -> usize {
        48
    }
}

impl<'de> Deserialize<'de> for PubKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let result: String = Deserialize::deserialize(deserializer)?;
        let result = hex_decode(&result).map_err(serde::de::Error::custom)?;
        let mut key = [0u8; 48];
        key.copy_from_slice(&result);
        Ok(Self(key))
    }
}

impl Serialize for PubKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let val = hex_encode(self.0);
        serializer.serialize_str(&val)
    }
}
