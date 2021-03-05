pub mod discovery;
pub mod protocol;
pub mod types;
use discv5::enr::CombinedKey;
use ssz::DecodeError;
use uint::construct_uint;

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
