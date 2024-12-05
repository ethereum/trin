use alloy::primitives::{B256, U256};
use rand::{thread_rng, Rng};

use crate::utils::partial_nibble_path_to_right_padded_b256;

#[derive(Debug, Clone)]
pub struct Filter {
    start_prefix: B256,
    end_prefix: B256,
}

impl Filter {
    pub fn new_random_filter(slice_count: u16) -> Self {
        // if slice_count is 0 or 1, we want to include the whole trie
        if slice_count == 0 || slice_count == 1 {
            return Self {
                start_prefix: B256::ZERO,
                end_prefix: B256::from(U256::MAX),
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
            start_prefix: B256::from(start_prefix),
            end_prefix: B256::from(end_prefix),
        }
    }

    pub fn is_included(&self, path: &[u8]) -> bool {
        let path = partial_nibble_path_to_right_padded_b256(path);
        (self.start_prefix..=self.end_prefix).contains(&path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_random_filter() {
        let filter = Filter::new_random_filter(0);
        assert_eq!(filter.start_prefix, B256::ZERO);
        assert_eq!(filter.end_prefix, B256::from(U256::MAX));

        let filter = Filter::new_random_filter(1);
        assert_eq!(filter.start_prefix, B256::ZERO);
        assert_eq!(filter.end_prefix, B256::from(U256::MAX));
    }

    #[test]
    fn test_is_included() {
        let filter = Filter {
            start_prefix: partial_nibble_path_to_right_padded_b256(&[0x1]),
            end_prefix: partial_nibble_path_to_right_padded_b256(&[0x3]),
        };

        assert!(!filter.is_included(&[0x00]));
        assert!(filter.is_included(&[0x01]));
        assert!(filter.is_included(&[0x02]));
        assert!(filter.is_included(&[0x03]));
        assert!(!filter.is_included(&[0x04]));
    }
}
