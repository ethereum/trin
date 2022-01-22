use crate::portalnet::types::uint::U256;
use hmac_sha256::Hash;
use sha3::{Digest, Keccak256};
use std::convert::TryInto;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VecToArrayError {
    #[error("Failed to convert vector to array. Expected length of {expected_len:?} but got length of {actual_len:?}")]
    Length {
        expected_len: usize,
        actual_len: usize,
    },
}

impl VecToArrayError {
    fn length<T>(v: Vec<T>, n: usize) -> Self {
        Self::Length {
            expected_len: n,
            actual_len: v.len(),
        }
    }
}

pub fn keccak256(key: &[u8]) -> U256 {
    let mut hasher = Keccak256::new();
    hasher.update(key);
    let result = &hasher.finalize()[..];
    U256::from(result)
}

pub fn sha256(key: &[u8]) -> U256 {
    let output = Hash::hash(key);
    U256::from(output)
}

pub fn vec_to_array<T, const N: usize>(v: Vec<T>) -> Result<[T; N], VecToArrayError> {
    v.try_into()
        .map_err(|v: Vec<T>| VecToArrayError::length(v, N))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_keccak256() {
        let test_input = hex::decode("302938402a9f").unwrap();
        let actual = keccak256(&test_input);
        let bytes = hex::decode("924fd25eb4fdce477517e48f6e4d25d2fe53139c7ebcd7a1ac102577a465e4ca")
            .unwrap();
        let expected = U256::from(vec_to_array(bytes).unwrap());
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_sha256() {
        let test_input = hex::decode("302938402a9f").unwrap();
        let actual = sha256(&test_input);
        let inter = hex::decode("20b2e507035deae9513e0622890508a27c8f79648aa5d7dcce0fe34fea6893df")
            .unwrap();
        let expected = U256::from(vec_to_array(inter).unwrap());
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_vec_to_array() {
        let input = vec![4, 2, 5, 6];
        let actual = vec_to_array(input).unwrap();
        let expected = [4, 2, 5, 6];
        assert_eq!(actual, expected);
    }

    #[test]
    #[should_panic]
    fn test_vec_to_array_failure() {
        let input = vec![4, 2, 5, 6];
        let _result = vec_to_array::<i32, 5>(input).unwrap();
    }
}
