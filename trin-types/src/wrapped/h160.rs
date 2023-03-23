use ethereum_types::H160 as H160Type;
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};

#[derive(Debug, PartialEq, Clone, Default, Deserialize, Serialize)]
pub struct H160(H160Type);

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
