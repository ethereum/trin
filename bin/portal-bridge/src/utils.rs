use std::time::{Duration, SystemTime};

use alloy::primitives::B256;
use discv5::enr::{CombinedKey, Enr, NodeId};
use ethportal_api::{
    consensus::constants::SECONDS_PER_SLOT, types::network_spec::network_spec,
    utils::bytes::hex_encode,
};

/// Generates a set of N private keys, with node ids that are equally spaced
/// around the 256-bit keys space.
// count as u8 is used as a safety precaution against foot-gunning, since it could
// take a long time with a bigger input. Separately, a value larger than 256
// stops getting evenly spread, because of how the code spreads the data by
// inspecting the first byte from the node ID. Also, values between 16 to
// 256 would be spread, but less and less evenly.
pub fn generate_spaced_private_keys(count: u8, root_private_key: Option<B256>) -> Vec<String> {
    let mut private_keys = vec![];
    let (root_node_id, root_private_key) = match root_private_key {
        Some(mut key) => {
            let private_key =
                CombinedKey::secp256k1_from_bytes(&mut key.0).expect("to be able to decode key");
            let enr = Enr::empty(&private_key).expect("to be able to build ENR from private key");
            (enr.node_id(), private_key)
        }
        None => random_node_id(),
    };
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
    let enr = Enr::empty(&random_private_key).expect("to be able to generate a random node id");
    (enr.node_id(), random_private_key)
}

/// Gets the duration until the next light client update
/// Updates are scheduled for 4 seconds into each slot
pub fn duration_until_next_update() -> Duration {
    let current_slot_timestamp = network_spec().slot_to_timestamp(network_spec().current_slot());

    // Calculate the update timestamp for current timestamp
    let mut next_update_timestamp = current_slot_timestamp + Duration::from_secs(4);

    // 4 seconds into current slot might have passed already, so we should try next slot
    loop {
        if let Ok(until_next_update) = next_update_timestamp.duration_since(SystemTime::now()) {
            return until_next_update;
        }
        next_update_timestamp += SECONDS_PER_SLOT;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use ethportal_api::{
        types::distance::{Metric, XorMetric},
        utils::bytes::hex_decode,
    };
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case(2)]
    #[case(4)]
    #[case(16)]
    fn test_generate_spaced_private_keys(#[case] count: u8) {
        use alloy::primitives::U256;

        let private_keys = generate_spaced_private_keys(count, None);
        assert_eq!(private_keys.len() as u8, count);
        let one = Enr::empty(
            &CombinedKey::secp256k1_from_bytes(&mut hex_decode(&private_keys[0]).unwrap()).unwrap(),
        )
        .unwrap();
        let two = Enr::empty(
            &CombinedKey::secp256k1_from_bytes(&mut hex_decode(&private_keys[1]).unwrap()).unwrap(),
        )
        .unwrap();
        let distance = XorMetric::distance(&one.node_id().raw(), &two.node_id().raw());
        let min_spread = (U256::MAX / U256::from(count) / U256::from(2)).into();
        let first_byte1 = one.node_id().raw()[0];
        let first_byte2 = two.node_id().raw()[0];
        assert!(
            distance > min_spread,
            "{distance} vs {min_spread}, first bytes: {first_byte1} vs {first_byte2}"
        );
    }
}
