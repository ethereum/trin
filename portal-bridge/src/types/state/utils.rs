use alloy_primitives::U256;

pub fn u256_to_lower_u64(u256: U256) -> u64 {
    let array: [u8; 32] = u256.to_be_bytes();
    let array: [u8; 8] = [
        array[24], array[25], array[26], array[27], array[28], array[29], array[30], array[31],
    ];
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
    }
}
