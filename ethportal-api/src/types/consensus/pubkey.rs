use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::{Decode, Encode};
use ssz_types::{typenum, FixedVector};
use std::ops::Deref;
use tree_hash_derive::TreeHash;

use crate::utils::bytes::{hex_decode, hex_encode};

/// Types based off specs @
/// https://github.com/ethereum/consensus-specs/blob/5970ae56a1/specs/phase0/beacon-chain.md
#[derive(Debug, PartialEq, Clone, TreeHash)]
pub struct PubKey {
    pub inner: FixedVector<u8, typenum::U48>,
}

impl Default for PubKey {
    fn default() -> Self {
        Self {
            inner: FixedVector::from_elem(0),
        }
    }
}

impl Deref for PubKey {
    type Target = FixedVector<u8, typenum::U48>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Decode for PubKey {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let key = FixedVector::from(Vec::from(bytes));
        Ok(Self { inner: key })
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
        buf.extend_from_slice(&self.inner.as_ssz_bytes());
    }
    fn ssz_bytes_len(&self) -> usize {
        self.inner.len()
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
        let key = FixedVector::from(result);
        Ok(Self { inner: key })
    }
}

impl Serialize for PubKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let val = hex_encode(self.inner.as_ssz_bytes());
        serializer.serialize_str(&val)
    }
}
