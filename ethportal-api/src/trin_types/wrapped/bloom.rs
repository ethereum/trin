use ethereum_types::Bloom as BloomType;
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};

#[derive(Debug, PartialEq, Clone, Default, Deserialize, Serialize)]
pub struct Bloom(BloomType);

impl Decode for Bloom {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(Self(BloomType::from_slice(bytes)))
    }
    fn ssz_fixed_len() -> usize {
        256
    }
}

impl Encode for Bloom {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.0.as_bytes());
    }
    fn ssz_bytes_len(&self) -> usize {
        256
    }
    fn ssz_fixed_len() -> usize {
        256
    }
}
