use crate::types::distance::{Metric, XorMetric};
use discv5::enr::NodeId;

pub fn generate_random_node_id(target_bucket_idx: u8, local_node_id: NodeId) -> NodeId {
    let distance_leading_zeroes = 255 - target_bucket_idx;
    let random_distance = crate::utils::bytes::random_32byte_array(distance_leading_zeroes);

    let raw_node_id = XorMetric::distance(&local_node_id.raw(), &random_distance);

    let raw_bytes = raw_node_id.big_endian();

    raw_bytes.into()
}
