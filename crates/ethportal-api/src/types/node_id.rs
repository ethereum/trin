use discv5::enr::NodeId;

use super::distance::{Metric, XorMetric};

/// Generate random NodeId based on bucket index target and a local node id.
/// First we generate a random distance metric with leading zeroes based on the target bucket.
/// Then we XOR the result distance with the local NodeId to get the random target NodeId
// TODO: We should be able to make this generic over a `Metric`.
pub fn generate_random_node_id(target_bucket_idx: u8, local_node_id: NodeId) -> NodeId {
    let distance_leading_zeroes = 255 - target_bucket_idx;
    let random_distance = crate::utils::bytes::random_32byte_array(distance_leading_zeroes);

    let raw_node_id = XorMetric::distance(&local_node_id.raw(), &random_distance);

    let raw_bytes = raw_node_id.big_endian();

    raw_bytes.into()
}

/// Generates `2 ^ unique_bits` random `NodeId`s.
///
/// The most significant bits of each `NodeId` will be unique.
///
/// The `unique_bits` has to be in `(0..=8)` range, panics otherwise. Can be easily upgraded to
/// support wider range.
pub fn generate_random_node_ids(unique_bits: u32) -> Vec<NodeId> {
    assert!(
        (0..=8).contains(&unique_bits),
        "Invalid bits value: {unique_bits}"
    );

    let insignificant_bits = u8::BITS - unique_bits;
    let insignificant_bits_mask = u8::MAX.checked_shr(unique_bits).unwrap_or_default();

    (0usize..1 << unique_bits)
        .map(|index| {
            // shift bits to most significant positions
            let unique_bits = (index as u8)
                .checked_shl(insignificant_bits)
                .unwrap_or_default();

            let mut node_id = rand::random::<[u8; 32]>();

            // set most significant bits of the first byte
            node_id[0] &= insignificant_bits_mask;
            node_id[0] |= unique_bits;

            NodeId::from(node_id)
        })
        .collect()
}
