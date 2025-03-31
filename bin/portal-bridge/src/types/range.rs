use std::collections::HashMap;

use trin_validation::constants::EPOCH_SIZE;

/// Converts a block range into a mapping of epoch indexes to block ranges.
///
/// An epoch is defined as a range of 8192 blocks, starting at 0.
/// The resulting HashMap contains:
/// - For epochs that are completely covered by the block range: None
/// - For epochs that are partially covered: Some((start_block, end_block)) where start_block and
///   end_block represent the actual block numbers that overlap with the epoch
///
/// # Returns
/// HashMap mapping epoch indexes to either None or Some((start_block, end_block))
pub fn block_range_to_epochs(start_block: u64, end_block: u64) -> HashMap<u64, Option<(u64, u64)>> {
    let mut epoch_map = HashMap::new();

    // Calculate start and end epochs
    let start_epoch = start_block / EPOCH_SIZE;
    let end_epoch = end_block / EPOCH_SIZE;

    // Process each epoch in the range
    for epoch in start_epoch..=end_epoch {
        // Calculate the first and last block of the current epoch
        let epoch_first_block = epoch * EPOCH_SIZE;
        let epoch_last_block = epoch_first_block + EPOCH_SIZE - 1;

        // Determine if the epoch is fully or partially covered
        if epoch_first_block >= start_block && epoch_last_block <= end_block {
            // Epoch is fully covered by the block range
            epoch_map.insert(epoch, None);
        } else {
            // Epoch is partially covered, calculate the overlap
            let overlap_start = start_block.max(epoch_first_block);
            let overlap_end = end_block.min(epoch_last_block);

            // Use actual block numbers instead of epoch-relative ones
            epoch_map.insert(epoch, Some((overlap_start, overlap_end)));
        }
    }

    epoch_map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_epoch_complete() {
        // Test a range that completely covers a single epoch
        let start = 8192; // Start of epoch 1
        let end = 16383; // End of epoch 1
        let result = block_range_to_epochs(start, end);

        assert_eq!(result.len(), 1);
        assert_eq!(result.get(&1), Some(&None));
    }

    #[test]
    fn test_single_epoch_partial() {
        // Test a range that partially covers a single epoch
        let start = 8500;
        let end = 9000;
        let result = block_range_to_epochs(start, end);

        assert_eq!(result.len(), 1);
        assert_eq!(result.get(&1), Some(&Some((8500, 9000))));
    }

    #[test]
    fn test_multiple_epochs() {
        // Test a range spanning multiple epochs
        let start = 8000; // In epoch 0
        let end = 17000; // In epoch 2
        let result = block_range_to_epochs(start, end);

        assert_eq!(result.len(), 3);
        assert_eq!(result.get(&0), Some(&Some((8000, 8191))));
        assert_eq!(result.get(&1), Some(&None));
        assert_eq!(result.get(&2), Some(&Some((16384, 17000))));
    }

    #[test]
    fn test_edge_cases() {
        // Test case where start and end are the same
        let result = block_range_to_epochs(5000, 5000);
        assert_eq!(result.len(), 1);
        assert_eq!(result.get(&0), Some(&Some((5000, 5000))));

        // Test exact epoch boundaries
        let result = block_range_to_epochs(0, 8191);
        assert_eq!(result.len(), 1);
        assert_eq!(result.get(&0), Some(&None));
    }
}
