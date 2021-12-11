use crate::portalnet::types::uint::U256;
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

pub fn keccak(key: &str) -> Result<U256, VecToArrayError> {
    let mut hasher = Keccak256::new();
    hasher.update(key);
    let result = hasher.finalize().to_vec();
    // if the underlying hash library is secure, then a 32 len vector will always be returned, so no error should ever occur
    Ok(U256::from(vec_to_array::<u8, 32>(result)?))
}

pub fn vec_to_array<T, const N: usize>(v: Vec<T>) -> Result<[T; N], VecToArrayError> {
    v.try_into()
        .map_err(|v: Vec<T>| VecToArrayError::length(v, N))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_keccak() {
        let test_input = "302938402a9f";
        let result = keccak(test_input).unwrap();
        let inter = hex::decode("3fea4dacec93ff6fd6a7462d1a2cc656f7a13361bb36abf0dde7c27a3ca7606d")
            .unwrap();
        let actual = U256::from(vec_to_array(inter).unwrap());
        assert_eq!(actual, result);
    }

    #[test]
    fn test_vec_to_array() {
        let input = vec![4, 2, 5, 6];
        let result = vec_to_array(input).unwrap();
        let actual = [4, 2, 5, 6];
        assert_eq!(result, actual);
    }

    #[test]
    #[should_panic]
    fn test_vec_to_array_failure() {
        let input = vec![4, 2, 5, 6];
        let _result = vec_to_array::<i32, 5>(input).unwrap();
    }
}
