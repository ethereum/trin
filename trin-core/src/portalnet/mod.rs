#![allow(clippy::all)]

use discv5::enr::CombinedKey;
use ssz::DecodeError;
use uint::construct_uint;

pub mod discovery;
pub mod events;
pub mod overlay;
pub mod storage;
pub mod types;
pub mod utp;

pub type Enr = discv5::enr::Enr<CombinedKey>;

construct_uint! {
    /// 256-bit unsigned integer.
    pub struct U256(4);
}

// Taken from https://github.com/sigp/lighthouse/blob/stable/consensus/ssz/src/encode/impls.rs
impl ssz::Encode for U256 {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        32
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let n = <Self as ssz::Encode>::ssz_fixed_len();
        let s = buf.len();

        buf.resize(s + n, 0);
        self.to_little_endian(&mut buf[s..]);
    }

    fn ssz_bytes_len(&self) -> usize {
        <Self as ssz::Encode>::ssz_fixed_len()
    }
}

// Taken from https://github.com/sigp/lighthouse/blob/stable/consensus/ssz/src/decode/impls.rs
impl ssz::Decode for U256 {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        32
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let len = bytes.len();
        let expected = <Self as ssz::Decode>::ssz_fixed_len();

        if len != expected {
            Err(DecodeError::InvalidByteLength { len, expected })
        } else {
            Ok(U256::from_little_endian(bytes))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ssz::{Decode, Encode};

    #[test]
    fn test_u256_ssz_encodes() {
        let msg = U256::from(60);
        let actual = msg.as_ssz_bytes();
        let decoded = U256::from_ssz_bytes(&actual).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(actual.len(), msg.ssz_bytes_len());
    }
}
