use alloy::primitives::U256;
use rand::{rng, Rng};

use crate::utils::nibbles_to_right_padded_b256;

#[derive(Debug, Clone)]
pub struct Filter {
    start: U256,
    end: U256,
}

impl Filter {
    /// Create a new filter that includes the whole trie
    /// Slice index must be less than slice count or it will panic
    pub fn new(slice_index: u16, slice_count: u16) -> Self {
        // if slice_count is 0 or 1, we want to include the whole trie
        if slice_count == 0 || slice_count == 1 {
            return Self {
                start: U256::ZERO,
                end: U256::MAX,
            };
        }

        assert!(
            slice_index < slice_count,
            "slice_index must be less than slice_count"
        );

        let slice_size = U256::MAX / U256::from(slice_count) + U256::from(1);

        let start = U256::from(slice_index) * slice_size;
        let end = if slice_index == slice_count - 1 {
            U256::MAX
        } else {
            start + slice_size - U256::from(1)
        };

        Self { start, end }
    }

    pub fn random(slice_count: u16) -> Self {
        // if slice_count is 0 or 1, we want to include the whole trie
        if slice_count == 0 || slice_count == 1 {
            return Self {
                start: U256::ZERO,
                end: U256::MAX,
            };
        }

        Self::new(rng().random_range(0..slice_count), slice_count)
    }

    /// Check if a path is included in the filter
    pub fn contains(&self, path: &[u8]) -> bool {
        // we need to use partial prefixes to not artificially exclude paths that are not exactly
        // the same length as the filter
        let shift_amount = 256 - path.len() * 4;
        let partial_start_prefix = (self.start >> shift_amount) << shift_amount;
        let partial_end_prefix = (self.end >> shift_amount) << shift_amount;
        let path = nibbles_to_right_padded_b256(path);

        (partial_start_prefix..=partial_end_prefix).contains(&path.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random() {
        let filter = Filter::random(0);
        assert_eq!(filter.start, U256::ZERO);
        assert_eq!(filter.end, U256::MAX);

        let filter = Filter::random(1);
        assert_eq!(filter.start, U256::ZERO);
        assert_eq!(filter.end, U256::MAX);
    }

    #[test]
    fn contains() {
        let filter = Filter {
            start: nibbles_to_right_padded_b256(&[0x1, 0x5, 0x5]).into(),
            end: nibbles_to_right_padded_b256(&[0x3]).into(),
        };

        assert!(!filter.contains(&[0x0]));
        assert!(filter.contains(&[0x1]));
        assert!(filter.contains(&[0x1, 0x5]));
        assert!(filter.contains(&[0x1, 0x5, 0x5]));
        assert!(!filter.contains(&[0x1, 0x5, 0x4]));
        assert!(filter.contains(&[0x2]));
        assert!(filter.contains(&[0x3]));
        assert!(!filter.contains(&[0x3, 0x0, 0x1]));
        assert!(!filter.contains(&[0x4]));
    }

    #[test]
    fn new() {
        let filter = Filter::new(0, 1);
        assert_eq!(filter.start, U256::ZERO);
        assert_eq!(filter.end, U256::MAX);

        let filter = Filter::new(0, 2);
        assert_eq!(filter.start, U256::ZERO);
        assert_eq!(filter.end, U256::MAX / U256::from(2));

        let filter = Filter::new(1, 2);
        assert_eq!(filter.start, U256::MAX / U256::from(2) + U256::from(1));
        assert_eq!(filter.end, U256::MAX);

        let filter = Filter::new(0, 3);
        assert_eq!(filter.start, U256::ZERO);
        assert_eq!(filter.end, U256::MAX / U256::from(3));

        let filter = Filter::new(1, 3);
        assert_eq!(filter.start, U256::MAX / U256::from(3) + U256::from(1));
        assert_eq!(
            filter.end,
            U256::MAX / U256::from(3) * U256::from(2) + U256::from(1)
        );

        let filter = Filter::new(2, 3);
        assert_eq!(
            filter.start,
            U256::MAX / U256::from(3) * U256::from(2) + U256::from(2)
        );
        assert_eq!(filter.end, U256::MAX);
    }
}
