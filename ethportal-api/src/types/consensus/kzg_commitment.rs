use crate::utils::bytes::{hex_decode, hex_encode};
use c_kzg::BYTES_PER_COMMITMENT;
use ethereum_hashing::hash_fixed;
use serde::{
    de::{Deserialize, Deserializer},
    ser::{Serialize, Serializer},
};
use ssz_derive::{Decode, Encode};
use std::{
    fmt,
    fmt::{Debug, Display, Formatter},
    str::FromStr,
};
use tree_hash::{Hash256, PackedEncoding, TreeHash};

pub const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;

#[derive(Clone, Copy, Encode, Decode, PartialEq, Eq, Hash)]
#[ssz(struct_behaviour = "transparent")]
pub struct KzgCommitment(pub [u8; BYTES_PER_COMMITMENT]);

impl KzgCommitment {
    pub fn calculate_versioned_hash(&self) -> Hash256 {
        let mut versioned_hash = hash_fixed(&self.0);
        versioned_hash[0] = VERSIONED_HASH_VERSION_KZG;
        Hash256::from_slice(versioned_hash.as_slice())
    }

    pub fn empty_for_testing() -> Self {
        KzgCommitment([0; c_kzg::BYTES_PER_COMMITMENT])
    }
}

impl From<KzgCommitment> for c_kzg::Bytes48 {
    fn from(value: KzgCommitment) -> Self {
        value.0.into()
    }
}

impl Display for KzgCommitment {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        for i in &self.0[0..2] {
            write!(f, "{i:02x}")?;
        }
        write!(f, "…")?;
        for i in &self.0[BYTES_PER_COMMITMENT - 2..BYTES_PER_COMMITMENT] {
            write!(f, "{i:02x}")?;
        }
        Ok(())
    }
}

impl TreeHash for KzgCommitment {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        <[u8; BYTES_PER_COMMITMENT] as TreeHash>::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        self.0.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        <[u8; BYTES_PER_COMMITMENT] as TreeHash>::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        self.0.tree_hash_root()
    }
}

impl Serialize for KzgCommitment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{self:?}"))
    }
}

impl<'de> Deserialize<'de> for KzgCommitment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        Self::from_str(&string).map_err(serde::de::Error::custom)
    }
}

impl FromStr for KzgCommitment {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex_decode(s).map_err(|e| e.to_string())?;
        if bytes.len() == BYTES_PER_COMMITMENT {
            let mut kzg_commitment_bytes = [0; BYTES_PER_COMMITMENT];
            kzg_commitment_bytes[..].copy_from_slice(&bytes);
            Ok(Self(kzg_commitment_bytes))
        } else {
            Err(format!(
                "InvalidByteLength: got {}, expected {}",
                bytes.len(),
                BYTES_PER_COMMITMENT
            ))
        }
    }
}

impl Debug for KzgCommitment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex_encode(self.0))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;

    const COMMITMENT_STR: &str = "0x53fa09af35d1d1a9e76f65e16112a9064ce30d1e4e2df98583f0f5dc2e7dd13a4f421a9c89f518fafd952df76f23adac";

    #[test]
    fn kzg_commitment_display() {
        let display_commitment_str = "0x53fa…adac";
        let display_commitment = KzgCommitment::from_str(COMMITMENT_STR).unwrap().to_string();

        assert_eq!(display_commitment, display_commitment_str);
    }

    #[test]
    fn kzg_commitment_debug() {
        let debug_commitment_str = COMMITMENT_STR;
        let debug_commitment = KzgCommitment::from_str(debug_commitment_str).unwrap();

        assert_eq!(format!("{debug_commitment:?}"), debug_commitment_str);
    }

    #[test]
    fn kzg_commitment_tree_hash_root() {
        let commitment = KzgCommitment::from_str(COMMITMENT_STR).unwrap();
        let root = commitment.tree_hash_root();
        let expected_root = commitment.0.tree_hash_root();

        assert_eq!(root, expected_root);
    }
}
