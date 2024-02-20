use serde::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode};
use tree_hash::{Hash256, PackedEncoding, TreeHash, TreeHashType};

/// A succinct representation of 8 boolean participation flags.
#[derive(Debug, Default, Clone, Copy, PartialEq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct ParticipationFlags {
    bits: u8,
}

/// Decode implementation that transparently behaves like the inner `u8`.
impl Decode for ParticipationFlags {
    fn is_ssz_fixed_len() -> bool {
        <u8 as Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <u8 as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        u8::from_ssz_bytes(bytes).map(|bits| Self { bits })
    }
}

/// Encode implementation that transparently behaves like the inner `u8`.
impl Encode for ParticipationFlags {
    fn is_ssz_fixed_len() -> bool {
        <u8 as Encode>::is_ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.bits.ssz_append(buf);
    }

    fn ssz_fixed_len() -> usize {
        <u8 as Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        self.bits.ssz_bytes_len()
    }

    fn as_ssz_bytes(&self) -> Vec<u8> {
        self.bits.as_ssz_bytes()
    }
}

impl TreeHash for ParticipationFlags {
    fn tree_hash_type() -> TreeHashType {
        u8::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        self.bits.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        u8::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> Hash256 {
        self.bits.tree_hash_root()
    }
}
