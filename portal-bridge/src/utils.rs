use discv5::enr::{CombinedKey, EnrBuilder, NodeId};
use ethportal_api::utils::bytes::hex_encode;
use ethportal_api::HistoryContentKey;
use ethportal_api::HistoryContentValue;
use serde::{Deserialize, Serialize};

/// Generates a set of N private keys, with node ids that are equally spaced
/// around the 256-bit keys space.
// count as u8 is used as a safety precaution against foot-gunning, since it could
// take a long time with a bigger input. Separately, a value larger than 256
// stops getting evenly spread, because of how the code spreads the data by
// inspecting the first byte from the node ID. Also, values between 16 to
// 256 would be spread, but less and less evenly.
pub fn generate_spaced_private_keys(count: u8) -> Vec<String> {
    let mut private_keys = vec![];
    let (root_node_id, root_private_key) = random_node_id();
    private_keys.push(hex_encode(root_private_key.encode()));
    let mut root_prefix = root_node_id.raw()[0];

    let mut prefixes: Vec<u8> = vec![];
    for _ in 1..count {
        let prefix = root_prefix.wrapping_add(u8::MAX / count);
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
    let enr = EnrBuilder::new("v4")
        .build(&random_private_key)
        .expect("to be able to generate a random node id");
    (enr.node_id(), random_private_key)
}

// Struct definitions for test assets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestAssets(pub Vec<Asset>);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub content_key: HistoryContentKey,
    pub content_value: HistoryContentValue,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ethereum_types::U256;
    use ethportal_api::types::distance::{Metric, XorMetric};
    use ethportal_api::utils::bytes::hex_decode;
    use rstest::rstest;

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
        let min_spread = (U256::MAX / count / 2).into();
        let first_byte1 = one.node_id().raw()[0];
        let first_byte2 = two.node_id().raw()[0];
        assert!(
            distance > min_spread,
            "{distance} vs {min_spread}, first bytes: {first_byte1} vs {first_byte2}"
        );
    }
}
