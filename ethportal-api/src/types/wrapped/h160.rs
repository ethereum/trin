use ethereum_types::H160 as H160Type;
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use tree_hash::{Hash256, TreeHash, TreeHashType};

#[derive(Debug, PartialEq, Clone, Default, Deserialize, Serialize)]
pub struct H160(H160Type);

impl TreeHash for H160 {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::Vector
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        let mut result = [0; 32];
        result[0..20].copy_from_slice(self.0.as_bytes());
        result.to_vec()
    }

    fn tree_hash_packing_factor() -> usize {
        1
    }

    fn tree_hash_root(&self) -> Hash256 {
        let mut result = [0; 32];
        result[0..20].copy_from_slice(self.0.as_bytes());
        Hash256::from_slice(&result)
    }
}

impl Decode for H160 {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(Self(H160Type::from_slice(bytes)))
    }
    fn ssz_fixed_len() -> usize {
        20
    }
}

impl Encode for H160 {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.0.as_bytes());
    }

    fn ssz_bytes_len(&self) -> usize {
        20
    }
    fn ssz_fixed_len() -> usize {
        20
    }
}
