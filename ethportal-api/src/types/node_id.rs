use super::enr::Enr;
use serde::{Deserialize, Serialize};
use stremio_serde_hex::{SerHex, StrictPfx};

use discv5::enr::NodeId as EnrNodeId;

use super::distance::{Metric, XorMetric};

type RawNodeId = [u8; 32];

/// Generate random NodeId based on bucket index target and a local node id.
/// First we generate a random distance metric with leading zeroes based on the target bucket.
/// Then we XOR the result distance with the local NodeId to get the random target NodeId
// TODO: We should be able to make this generic over a `Metric`.
pub fn generate_random_node_id(target_bucket_idx: u8, local_node_id: EnrNodeId) -> EnrNodeId {
    let distance_leading_zeroes = 255 - target_bucket_idx;
    let random_distance = crate::utils::bytes::random_32byte_array(distance_leading_zeroes);

    let raw_node_id = XorMetric::distance(&local_node_id.raw(), &random_distance);

    let raw_bytes = raw_node_id.big_endian();

    raw_bytes.into()
}

/// Discv5 NodeId
// TODO: Wrap this type over discv5::NodeId type
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct NodeId(#[serde(with = "SerHex::<StrictPfx>")] pub RawNodeId);

impl From<&Enr> for NodeId {
    fn from(enr: &Enr) -> Self {
        NodeId(enr.node_id().raw())
    }
}

impl From<Enr> for NodeId {
    fn from(enr: Enr) -> Self {
        NodeId(enr.node_id().raw())
    }
}

impl From<EnrNodeId> for NodeId {
    fn from(value: EnrNodeId) -> Self {
        NodeId(value.raw())
    }
}

impl From<NodeId> for EnrNodeId {
    fn from(val: NodeId) -> Self {
        EnrNodeId::new(&val.0)
    }
}
