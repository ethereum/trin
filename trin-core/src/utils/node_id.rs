use crate::utils::bytes;
use crate::utils::distance::xor;
use discv5::enr::NodeId;

#[cfg(test)]
use crate::portalnet::Enr;
#[cfg(test)]
use discv5::enr::{CombinedKey, EnrBuilder};
#[cfg(test)]
use rand::Rng;
#[cfg(test)]
use std::net::Ipv4Addr;

/// Generate random NodeId based on bucket index target and a local node id.
/// First we generate a random distance metric with leading zeroes based on the target bucket.
/// Then we XOR the result distance with the local NodeId to get the random target NodeId
pub fn generate_random_node_id(
    target_bucket_idx: u8,
    local_node_id: NodeId,
) -> anyhow::Result<NodeId> {
    let distance_leading_zeroes = 255 - target_bucket_idx;
    let random_distance = bytes::random_32byte_array(distance_leading_zeroes);
    let raw_node_id = xor(&local_node_id.raw(), &random_distance);
    match NodeId::parse(raw_node_id.to_32_byte_array().as_slice()) {
        Ok(node_id) => Ok(node_id),
        Err(msg) => Err(anyhow::Error::msg(msg)),
    }
}

#[cfg(test)]
pub fn generate_random_remote_enr() -> (CombinedKey, Enr) {
    let key = CombinedKey::generate_secp256k1();

    let mut rng = rand::thread_rng();
    let ip = Ipv4Addr::from(rng.gen::<u32>());

    let enr = EnrBuilder::new("v4")
        .ip(ip.into())
        .udp(8000)
        .build(&key)
        .unwrap();

    (key, enr)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_generate_random_node_id_1() {
        let target_bucket_idx: u8 = 5;
        let local_node_id = NodeId::random();
        let random_node_id = generate_random_node_id(target_bucket_idx, local_node_id).unwrap();
        let distance = xor(&random_node_id.raw(), &local_node_id.raw());
        let distance = distance.to_32_byte_array();

        assert_eq!(distance[0..31], vec![0; 31]);
        assert!(distance[31] < 64 && distance[31] >= 32)
    }

    #[test]
    fn test_generate_random_node_id_2() {
        let target_bucket_idx: u8 = 0;
        let local_node_id = NodeId::random();
        let random_node_id = generate_random_node_id(target_bucket_idx, local_node_id).unwrap();
        let distance = xor(&random_node_id.raw(), &local_node_id.raw());
        let distance = distance.to_32_byte_array();

        assert_eq!(distance[0..31], vec![0; 31]);
        assert_eq!(distance[31], 1);
    }

    #[test]
    fn test_generate_random_node_id_3() {
        let target_bucket_idx: u8 = 255;
        let local_node_id = NodeId::random();
        let random_node_id = generate_random_node_id(target_bucket_idx, local_node_id).unwrap();
        let distance = xor(&random_node_id.raw(), &local_node_id.raw());
        let distance = distance.to_32_byte_array();

        assert!(distance[0] > 127);
    }
}
