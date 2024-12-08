use alloy::primitives::{B256, U256};
use rand::{thread_rng, Rng};

use crate::utils::partial_nibble_path_to_right_padded_b256;

#[derive(Debug, Clone)]
pub struct Filter {
    start_prefix: U256,
    end_prefix: U256,
}

impl Filter {
    pub fn new_random_filter(slice_count: u16) -> Self {
        // if slice_count is 0 or 1, we want to include the whole trie
        if slice_count == 0 || slice_count == 1 {
            return Self {
                start_prefix: U256::ZERO,
                end_prefix: U256::MAX,
            };
        }

        let slice_size = U256::MAX / U256::from(slice_count);
        let random_slice_index = thread_rng().gen_range(0..slice_count);

        let start_prefix = U256::from(random_slice_index) * slice_size;
        let end_prefix = if random_slice_index == slice_count - 1 {
            U256::MAX
        } else {
            start_prefix + slice_size - U256::from(1)
        };

        Self {
            start_prefix,
            end_prefix,
        }
    }

    fn partial_prefix(prefix: U256, shift_amount: usize) -> B256 {
        prefix
            .arithmetic_shr(shift_amount)
            .wrapping_shl(shift_amount)
            .into()
    }

    pub fn is_included(&self, path: &[u8]) -> bool {
        // we need to use partial prefixes to not artificially exclude paths that are not exactly
        // the same length as the filter
        let shift_amount = 256 - path.len() * 4;
        let partial_start_prefix = Filter::partial_prefix(self.start_prefix, shift_amount);
        let partial_end_prefix = Filter::partial_prefix(self.end_prefix, shift_amount);
        let path = partial_nibble_path_to_right_padded_b256(path);

        (partial_start_prefix..=partial_end_prefix).contains(&path)
    }
}

#[cfg(test)]
mod tests {
    use alloy::hex::FromHex;

    use super::*;

    #[test]
    fn test_new_random_filter() {
        let filter = Filter::new_random_filter(0);
        assert_eq!(filter.start_prefix, U256::ZERO);
        assert_eq!(filter.end_prefix, U256::MAX);

        let filter = Filter::new_random_filter(1);
        assert_eq!(filter.start_prefix, U256::ZERO);
        assert_eq!(filter.end_prefix, U256::MAX);
    }

    #[test]
    fn test_is_included() {
        let filter = Filter {
            start_prefix: partial_nibble_path_to_right_padded_b256(&[0x1, 0x5, 0x5]).into(),
            end_prefix: partial_nibble_path_to_right_padded_b256(&[0x3]).into(),
        };

        assert!(!filter.is_included(&[0x0]));
        assert!(filter.is_included(&[0x1]));
        assert!(filter.is_included(&[0x1, 0x5]));
        assert!(filter.is_included(&[0x1, 0x5, 0x5]));
        assert!(!filter.is_included(&[0x1, 0x5, 0x4]));
        assert!(filter.is_included(&[0x2]));
        assert!(filter.is_included(&[0x3]));
        assert!(!filter.is_included(&[0x4]));
    }

    #[test]
    fn test_partial_prefix() {
        let prefix: &[u8] = &[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8];
        let prefix: U256 = partial_nibble_path_to_right_padded_b256(prefix).into();

        assert_eq!(
            Filter::partial_prefix(prefix, 256),
            B256::from_hex("0x0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
        );

        assert_eq!(
            Filter::partial_prefix(prefix, 256 - 4),
            B256::from_hex("0x1000000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
        );

        assert_eq!(
            Filter::partial_prefix(prefix, 256 - 4 * 4),
            B256::from_hex("0x1234000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
        );

        assert_eq!(
            Filter::partial_prefix(prefix, 256 - 5 * 4),
            B256::from_hex("0x1234500000000000000000000000000000000000000000000000000000000000")
                .unwrap()
        );
    }
}
