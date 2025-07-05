use alloy::primitives::U256;

const CYCLE_BITS: usize = 16;
const CYCLE_BITS_BITMAP: u64 = (1 << CYCLE_BITS) - 1;

/// Creates content id that can be used for range queries.
pub fn range_content_id(block_number: u64, content_type: u8) -> [u8; 32] {
    // extract the 16 least significant bits
    let cycle_bits = block_number & CYCLE_BITS_BITMAP;

    // extract the 48 most significant bits
    let offset_bits = block_number & !CYCLE_BITS_BITMAP;

    // make cycle bits most significant, reverse and make offset bits least significant
    let content_id_prefix = cycle_bits.rotate_right(CYCLE_BITS as u32) | offset_bits.reverse_bits();

    // create content_id as U256
    let content_id = U256::from_limbs([content_type as u64, 0, 0, content_id_prefix]);

    content_id.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{b256, B256};
    use rstest::rstest;

    use super::*;
    use crate::types::content_key::history::{
        HISTORY_BLOCK_BODY_KEY_PREFIX, HISTORY_BLOCK_RECEIPTS_KEY_PREFIX,
    };

    #[rstest]
    #[case::zero(0, 0, B256::ZERO)]
    #[case::genesis_block_body(
        0,
        HISTORY_BLOCK_BODY_KEY_PREFIX,
        B256::with_last_byte(HISTORY_BLOCK_BODY_KEY_PREFIX)
    )]
    #[case::genesis_receipts(
        0,
        HISTORY_BLOCK_RECEIPTS_KEY_PREFIX,
        B256::with_last_byte(HISTORY_BLOCK_RECEIPTS_KEY_PREFIX)
    )]
    #[case::block_number_12345678_block_body(
        12_345_678,
        HISTORY_BLOCK_BODY_KEY_PREFIX,
        b256!("0x614e3d0000000000000000000000000000000000000000000000000000000009"),
    )]
    #[case::block_number_12345678_receipts(
        12_345_678,
        HISTORY_BLOCK_RECEIPTS_KEY_PREFIX,
        b256!("0x614e3d000000000000000000000000000000000000000000000000000000000A"),
    )]
    fn simple(
        #[case] block_number: u64,
        #[case] content_type: u8,
        #[case] expected_content_id: B256,
    ) {
        assert_eq!(
            range_content_id(block_number, content_type),
            expected_content_id,
        )
    }
}
