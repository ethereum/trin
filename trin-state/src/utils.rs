use ethereum_types::U256;
use num::{
    bigint::{BigInt, Sign},
    Signed,
};

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

trait FromU256 {
    fn from_u256(n: U256) -> Self;
}

impl FromU256 for BigInt {
    fn from_u256(n: U256) -> Self {
        let mut bytes: [u8; 32] = [0u8; 32];
        n.to_little_endian(&mut bytes);
        BigInt::from_bytes_le(Sign::Plus, &bytes)
    }
}

trait ToU256 {
    fn to_u256(&self) -> Result<U256, String>;
}

impl ToU256 for BigInt {
    fn to_u256(&self) -> Result<U256, String> {
        let (sign, bytes) = self.to_bytes_be();
        match sign {
            Sign::Plus => Ok(U256::from_big_endian(&bytes)),
            Sign::Minus => Err("Cannot convert negative BigInt to unsigned int".to_string()),
            Sign::NoSign => Ok(U256::from_big_endian(&bytes)),
        }
    }
}

// distance function as defined at...
// https://notes.ethereum.org/h58LZcqqRRuarxx4etOnGQ#Storage-Layout
// todo: measure performance & optimize if necessary
pub fn distance(node_id: U256, content_id: U256) -> Result<U256, String> {
    let node_id_int = BigInt::from_u256(node_id);
    let content_id_int = BigInt::from_u256(content_id);
    let modulo = BigInt::parse_bytes(&MODULO, 10).unwrap();
    let mid = BigInt::parse_bytes(&MID, 10).unwrap();
    let negative_mid = mid
        .checked_mul(&BigInt::from_bytes_le(Sign::Minus, &[1u8]))
        .unwrap();

    let first_phrase = node_id_int - content_id_int + &mid;
    // % returns the remainder, we want to return the modulus
    let modulus_result = ((first_phrase % &modulo) + &modulo) % &modulo;
    let delta = modulus_result - &mid;
    match delta < negative_mid {
        true => (delta + mid).abs().to_u256(),
        _ => delta.abs().to_u256(),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use test_log::test;

    // 2 ** 256 - 1
    const MOD_SUB_ONE: &str =
        "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    // 2 ** 255
    const MID_DEC_STR: &str =
        "57896044618658097711785492504343953926634992332820282019728792003956564819968";

    #[test]
    fn test_number_conversion() {
        let number = "10";
        let u_256 = U256::from_dec_str(number).unwrap();
        let big_int = BigInt::from_u256(u_256);
        let next = big_int.to_u256().unwrap();
        assert_eq!(next, u_256)
    }

    //test cases yanked from: https://notes.ethereum.org/h58LZcqqRRuarxx4etOnGQ
    #[test]
    fn test_distance_with_zeros() {
        let content_id = U256::from_dec_str("10").unwrap();
        let node_id = U256::from_dec_str("10").unwrap();
        let expected = U256::from_dec_str("0").unwrap();
        let calculated_distance = distance(content_id, node_id).unwrap();
        assert_eq!(calculated_distance, expected);
    }

    #[test]
    fn test_distance_one() {
        let content_id = U256::from_dec_str("5").unwrap();
        let node_id = U256::from_dec_str("1").unwrap();
        let expected = U256::from_dec_str("4").unwrap();
        let calculated_distance = distance(content_id, node_id).unwrap();
        assert_eq!(calculated_distance, expected);
        let reversed = distance(node_id, content_id).unwrap();
        assert_eq!(reversed, expected);
    }

    #[test]
    fn test_distance_two() {
        let content_id = U256::from_dec_str("5").unwrap();
        let node_id = U256::from_dec_str(MOD_SUB_ONE).unwrap();
        let expected = U256::from_dec_str("6").unwrap();
        let calculated_distance = distance(content_id, node_id).unwrap();
        assert_eq!(calculated_distance, expected);
    }

    #[test]
    fn test_distance_three() {
        let content_id = U256::from_dec_str(MOD_SUB_ONE).unwrap();
        let node_id = U256::from_dec_str("6").unwrap();
        let expected = U256::from_dec_str("7").unwrap();
        let calculated_distance = distance(content_id, node_id).unwrap();
        assert_eq!(calculated_distance, expected);
    }

    #[test]
    fn test_distance_four() {
        let content_id = U256::from_dec_str("0").unwrap();
        let node_id = U256::from_dec_str(MID_DEC_STR).unwrap();
        let expected = U256::from_dec_str(MID_DEC_STR).unwrap();
        let calculated_distance = distance(content_id, node_id).unwrap();
        assert_eq!(calculated_distance, expected);
    }

    #[test]
    fn test_distance_five() {
        let content_id = U256::from_dec_str("0").unwrap();
        // 2 ** 255 + 1
        let node_id = U256::from_dec_str(
            "57896044618658097711785492504343953926634992332820282019728792003956564819969",
        )
        .unwrap();
        // 2 ** 255 - 1
        let expected = U256::from_dec_str(
            "57896044618658097711785492504343953926634992332820282019728792003956564819967",
        )
        .unwrap();
        let calculated_distance = distance(content_id, node_id).unwrap();
        assert_eq!(calculated_distance, expected);
    }
}
