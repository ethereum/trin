use std::convert::TryInto;

use ssz::DecodeError;
use thiserror::Error;
use uint::construct_uint;

construct_uint! {
    /// 512-bit unsigned integer
    pub struct U512(8);
}

// taken from primitive-messages crate https://docs.rs/primitive-types/0.10.1/src/primitive_types/lib.rs.html#147-155
impl From<U256> for U512 {
    fn from(value: U256) -> U512 {
        let U256(ref arr) = value;
        let mut ret = [0; 8];
        ret[0] = arr[0];
        ret[1] = arr[1];
        ret[2] = arr[2];
        ret[3] = arr[3];
        U512(ret)
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum U512toU256Error {
    #[error("Failed to convert U512 to U256 due to overflow")]
    Overflow,
}

impl TryInto<U256> for U512 {
    type Error = U512toU256Error;

    fn try_into(self) -> Result<U256, Self::Error> {
        let U512(ref arr) = self;

        if arr[4] | arr[5] | arr[6] | arr[7] != 0 {
            return Err(U512toU256Error::Overflow);
        }

        let mut ret = [0; 4];
        ret[0] = arr[0];
        ret[1] = arr[1];
        ret[2] = arr[2];
        ret[3] = arr[3];
        Ok(U256(ret))
    }
}

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
    use super::U512toU256Error::Overflow;
    use super::*;
    use rstest::rstest;
    use ssz::{Decode, Encode};

    const U256_MAX: U256 = U256([u64::MAX, u64::MAX, u64::MAX, u64::MAX]);
    const U512_MAX: U512 = U512([u64::MAX, u64::MAX, u64::MAX, u64::MAX, 0, 0, 0, 0]);

    #[rstest]
    #[case(U256([1,2,3,4]), U512([1,2,3,4,0,0,0,0]))]
    #[case(U256([492,4039,129,9984]), U512([492,4039,129,9984,0,0,0,0]))]
    #[case(U256_MAX, U512_MAX)]
    #[case(U256([u64::MAX,u64::MAX,u64::MAX-1,u64::MAX]), U512([u64::MAX,u64::MAX,u64::MAX-1,u64::MAX,0,0,0,0]))]
    #[case(U256([0,0,0,0]), U512([0,0,0,0,0,0,0,0]))]
    fn test_u256_to_u512(#[case] input: U256, #[case] expected: U512) {
        let result = U512::from(input);
        assert_eq!(expected, result);
    }

    #[rstest]
    #[case(U512([1,2,3,4,0,0,0,0]), U256([1,2,3,4]))]
    #[case(U512([419,70,409,96,0,0,0,0]), U256([419,70,409,96]))]
    #[case(U512([u64::MAX,u64::MAX,u64::MAX,u64::MAX,0,0,0,0]), U256_MAX)]
    #[case(U512([u64::MAX-1,u64::MAX,u64::MAX,u64::MAX,0,0,0,0]), U256([u64::MAX-1,u64::MAX,u64::MAX,u64::MAX]))]
    #[case(U512([1,0,0,0,0,0,0,0]), U256([1,0,0,0]))]
    fn test_u512_to_u256(#[case] input: U512, #[case] expected: U256) {
        let result = input.try_into().unwrap();
        assert_eq!(expected, result);
    }

    #[rstest]
    #[case(U512([1,2,3,4,1,0,0,0]), Overflow)]
    #[case(U512([1,2,3,4,0,34,0,0]), Overflow)]
    #[case(U512([1,2,3,4,0,0,234,0]), Overflow)]
    #[case(U512([1,2,3,4,0,0,0,349]), Overflow)]
    #[case(U512([u64::MAX,u64::MAX,u64::MAX,u64::MAX,1,0,0,0]), Overflow)]
    #[case(U512([0,0,0,0,1,0,0,0]), Overflow)]
    fn test_u512_to_u256_failure(#[case] input: U512, #[case] expected: U512toU256Error) {
        let result: Result<U256, U512toU256Error> = input.try_into();
        if let Err(e) = result {
            assert_eq!(e, expected);
        }
    }

    #[test]
    fn test_u256_ssz_encodes() {
        let msg = U256::from(60);
        let actual = msg.as_ssz_bytes();
        let decoded = U256::from_ssz_bytes(&actual).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(actual.len(), msg.ssz_bytes_len());
    }
}
