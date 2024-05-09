use alloy_primitives::U256;

pub fn u256_to_lower_u64(u256: U256) -> u64 {
    let mut array = [0u8; 8];
    array.copy_from_slice(&u256.to_be_bytes::<32>()[24..]);
    u64::from_be_bytes(array)
}

#[cfg(test)]
mod tests {
    use crate::types::state::utils::u256_to_lower_u64;
    use alloy_primitives::U256;

    #[test]
    fn test_u256_to_lower_u64() {
        assert_eq!(u256_to_lower_u64(U256::from(5)), 5);
        assert_eq!(u256_to_lower_u64(U256::from(4444444)), 4444444);
        assert_eq!(
            u256_to_lower_u64(U256::from(1221212112121212u64)),
            1221212112121212
        );
        assert_eq!(u256_to_lower_u64(U256::MAX), u64::MAX);
    }
}
