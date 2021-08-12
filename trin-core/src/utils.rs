use directories::ProjectDirs;
use std::{env, fs};

use num::bigint::{BigInt, Sign};
use num::Signed;

const TRIN_DATA_ENV_VAR: &str = "TRIN_DATA_PATH";

pub fn xor_two_values(first: &[u8], second: &[u8]) -> Vec<u8> {
    if first.len() != second.len() {
        panic!("Can only xor vectors of equal length.")
    };

    first
        .iter()
        .zip(&mut second.iter())
        .map(|(&first, &second)| first ^ second)
        .collect()
}

// 2 ** 256
const MODULO: [u8; 78] = [
    49, 49, 53, 55, 57, 50, 48, 56, 57, 50, 51, 55, 51, 49, 54, 49, 57, 53, 52, 50, 51, 53, 55, 48,
    57, 56, 53, 48, 48, 56, 54, 56, 55, 57, 48, 55, 56, 53, 51, 50, 54, 57, 57, 56, 52, 54, 54, 53,
    54, 52, 48, 53, 54, 52, 48, 51, 57, 52, 53, 55, 53, 56, 52, 48, 48, 55, 57, 49, 51, 49, 50, 57,
    54, 51, 57, 57, 51, 54,
];

// 2 ** 255
const MID: [u8; 77] = [
    53, 55, 56, 57, 54, 48, 52, 52, 54, 49, 56, 54, 53, 56, 48, 57, 55, 55, 49, 49, 55, 56, 53, 52,
    57, 50, 53, 48, 52, 51, 52, 51, 57, 53, 51, 57, 50, 54, 54, 51, 52, 57, 57, 50, 51, 51, 50, 56,
    50, 48, 50, 56, 50, 48, 49, 57, 55, 50, 56, 55, 57, 50, 48, 48, 51, 57, 53, 54, 53, 54, 52, 56,
    49, 57, 57, 54, 56,
];

// distance function as defined at...
// https://notes.ethereum.org/h58LZcqqRRuarxx4etOnGQ#Storage-Layout
// todo: measure & optimize
pub fn distance(node_id: BigInt, content_id: BigInt) -> BigInt {
    let modulo = BigInt::parse_bytes(&MODULO, 10).unwrap();
    let mid = BigInt::parse_bytes(&MID, 10).unwrap();
    let negative_mid = mid
        .checked_mul(&BigInt::from_bytes_le(Sign::Minus, &[1u8]))
        .unwrap();

    let first_phrase = node_id - content_id + &mid;
    // % returns the remainder, we want to return the modulus
    let modulus_result = ((first_phrase % &modulo) + &modulo) % &modulo;
    let delta = modulus_result - &mid;
    match delta < negative_mid {
        true => (delta + mid).abs(),
        _ => delta.abs(),
    }
}

pub fn get_data_dir() -> String {
    let path = env::var(TRIN_DATA_ENV_VAR).unwrap_or_else(|_| get_default_data_dir());

    fs::create_dir_all(&path).expect("Unable to create data directory folder");
    path
}

pub fn get_default_data_dir() -> String {
    // Windows: C:\Users\Username\AppData\Roaming\Trin\data
    // macOS: ~/Library/Application Support/Trin
    // Unix-like: ~/.trin

    match ProjectDirs::from("", "", "Trin") {
        Some(proj_dirs) => proj_dirs.data_local_dir().to_str().unwrap().to_string(),
        None => panic!("Unable to find data directory"),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // 2 ** 256 - 1
    const MOD_SUB_ONE: &[u8] =
        "115792089237316195423570985008687907853269984665640564039457584007913129639935".as_bytes();

    #[test]
    fn test_xor_two_zeros() {
        let one = vec![0];
        let two = vec![0];
        assert_eq!(xor_two_values(&one, &two), [0]);
    }

    #[test]
    fn test_xor_two_values() {
        let one = vec![1, 0, 0];
        let two = vec![0, 0, 1];
        assert_eq!(xor_two_values(&one, &two), [1, 0, 1]);
    }

    #[test]
    #[should_panic(expected = "Can only xor vectors of equal length.")]
    fn test_xor_panics_with_different_lengths() {
        let one = vec![1, 0];
        let two = vec![0, 0, 1];
        xor_two_values(&one, &two);
    }

    // test cases yanked from: https://notes.ethereum.org/h58LZcqqRRuarxx4etOnGQ
    #[test]
    fn test_distance_zeros() {
        let content_id = BigInt::parse_bytes("10".as_bytes(), 10).unwrap();
        let node_id = BigInt::parse_bytes("10".as_bytes(), 10).unwrap();
        let expected = BigInt::parse_bytes("0".as_bytes(), 10).unwrap();
        let calculated_distance = distance(content_id, node_id);
        assert_eq!(calculated_distance, expected);
    }

    #[test]
    fn test_distance_one() {
        let content_id = BigInt::parse_bytes("5".as_bytes(), 10).unwrap();
        let node_id = BigInt::parse_bytes("1".as_bytes(), 10).unwrap();
        let expected = BigInt::parse_bytes("4".as_bytes(), 10).unwrap();
        let calculated_distance = distance(content_id.clone(), node_id.clone());
        assert_eq!(calculated_distance, expected);
        let reversed = distance(node_id, content_id);
        assert_eq!(reversed, expected);
    }

    #[test]
    fn test_distance_two() {
        let content_id = BigInt::parse_bytes("5".as_bytes(), 10).unwrap();
        let node_id = BigInt::parse_bytes(MOD_SUB_ONE, 10).unwrap();
        let expected = BigInt::parse_bytes("6".as_bytes(), 10).unwrap();
        let calculated_distance = distance(content_id, node_id);
        assert_eq!(calculated_distance, expected);
    }

    #[test]
    fn test_distance_three() {
        let content_id = BigInt::parse_bytes(MOD_SUB_ONE, 10).unwrap();
        let node_id = BigInt::parse_bytes("6".as_bytes(), 10).unwrap();
        let expected = BigInt::parse_bytes("7".as_bytes(), 10).unwrap();
        let calculated_distance = distance(content_id, node_id);
        assert_eq!(calculated_distance, expected);
    }

    #[test]
    fn test_distance_four() {
        let content_id = BigInt::parse_bytes("0".as_bytes(), 10).unwrap();
        let node_id = BigInt::parse_bytes(&MID, 10).unwrap();
        let expected = BigInt::parse_bytes(&MID, 10).unwrap();
        let calculated_distance = distance(content_id, node_id);
        assert_eq!(calculated_distance, expected);
    }

    #[test]
    fn test_distance_five() {
        let content_id = BigInt::parse_bytes("0".as_bytes(), 10).unwrap();
        // 2 ** 255 + 1
        let node_id = BigInt::parse_bytes(
            "57896044618658097711785492504343953926634992332820282019728792003956564819969"
                .as_bytes(),
            10,
        )
        .unwrap();
        // 2 ** 255 - 1
        let expected = BigInt::parse_bytes(
            "57896044618658097711785492504343953926634992332820282019728792003956564819967"
                .as_bytes(),
            10,
        )
        .unwrap();
        let calculated_distance = distance(content_id, node_id);
        assert_eq!(calculated_distance, expected);
    }
}
