use crate::constants::BATCH_SIZE;
use discv5::enr::{CombinedKey, EnrBuilder, NodeId};
use std::ops::Range;
use trin_utils::bytes::hex_encode;

/// Splits a range into chunks of (at most) BATCH_SIZE,
/// Used in "latest" mode, since most "chunks" will contain only a couple headers
pub fn get_ranges(range: &Range<u64>) -> Vec<Range<u64>> {
    let mut ranges = vec![];
    let mut index = range.start;
    while index < range.end {
        let end = std::cmp::min(index + BATCH_SIZE, range.end);
        let range = Range { start: index, end };
        ranges.push(range);
        index += BATCH_SIZE;
    }
    ranges
}

pub fn generate_spaced_private_keys(count: u8) -> Vec<String> {
    if count > 16 {
        panic!("count must be less than 16");
    }
    let mut private_keys = vec![];
    let (root_node_id, root_private_key) = random_node_id();
    private_keys.push(hex_encode(root_private_key.encode()));
    let mut root_prefix = root_node_id.raw()[0];

    let mut prefixes: Vec<u8> = vec![];
    for i in 1..count {
        let prefix = root_prefix.wrapping_add(u8::MAX / i);
        prefixes.push(prefix);
        root_prefix = prefix;
    }

    for prefix in prefixes {
        let (mut node_id, mut private_key) = random_node_id();
        while node_id.raw()[0] != prefix {
            (node_id, private_key) = random_node_id();
        }
        private_keys.push(hex_encode(private_key.encode()));
    }
    private_keys
}

fn random_node_id() -> (NodeId, CombinedKey) {
    let random_private_key = CombinedKey::generate_secp256k1();
    let enr = EnrBuilder::new("v4").build(&random_private_key).unwrap();
    (enr.node_id(), random_private_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethereum_types::U256;
    use rstest::rstest;
    use trin_types::distance::{Metric, XorMetric};
    use trin_utils::bytes::hex_decode;

    #[rstest]
    #[case(2)]
    #[case(4)]
    #[case(16)]
    fn test_generate_spaced_private_keys(#[case] count: u8) {
        let private_keys = generate_spaced_private_keys(count);
        assert_eq!(private_keys.len() as u8, count);
        let one = EnrBuilder::new("v4")
            .build(
                &CombinedKey::secp256k1_from_bytes(&mut hex_decode(&private_keys[0]).unwrap())
                    .unwrap(),
            )
            .unwrap();
        let two = EnrBuilder::new("v4")
            .build(
                &CombinedKey::secp256k1_from_bytes(&mut hex_decode(&private_keys[1]).unwrap())
                    .unwrap(),
            )
            .unwrap();
        let distance = XorMetric::distance(&one.node_id().raw(), &two.node_id().raw());
        assert!(distance < (U256::MAX / count).into());
    }
}
