#![allow(clippy::all)]

use discv5::enr::CombinedKey;
use ssz::DecodeError;
use uint::construct_uint;

pub mod discovery;
pub mod events;
pub mod overlay;
pub mod types;
<<<<<<< HEAD
pub mod utp;
=======
pub mod storage;

use std::convert::From;
use std::vec;
>>>>>>> WIP storage class

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

impl From<vec::Vec<u8>> for U256 {

    fn from(vec: vec::Vec<u8>) -> U256 {

        let mut result = U256::from(0);
        let mut byte_position = vec.len();

        for byte in vec {

            let base: u8 = 2;
            let power: u32 = 8 * (byte_position - 1) as u32;

            result = result + (byte * (base.pow(power)));
            byte_position = byte_position - 1;

        }

        result

    } 

}

impl U256 {

    fn max() -> U256 {

        let base: u128 = 2;
        let power: u32 = 127;

        let half_max_128: u128 = base.pow(power);

        let max_256: U256 = ((U256::from(half_max_128) << 129) + (U256::from(half_max_128) * 2)) - 1;

        max_256

    }

}

