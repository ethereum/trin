use super::enr::Enr;
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use stremio_serde_hex::{SerHex, StrictPfx};

use discv5::enr::NodeId as EnrNodeId;

use super::distance::{Metric, XorMetric};

type RawNodeId = [u8; 32];

/// Discv5 NodeId
// TODO: Wrap this type over discv5::NodeId type
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct NodeId(#[serde(with = "SerHex::<StrictPfx>")] pub RawNodeId);

impl NodeId {
    pub fn random() -> Self {
        Self(rand::random())
    }

    pub fn raw(self) -> RawNodeId {
        *self.deref()
    }

    /// Generate random NodeId based on bucket index target and a local node id.
    /// First we generate a random distance metric with leading zeroes based on the target bucket.
    /// Then we XOR the result distance with the local NodeId to get the random target NodeId
    // TODO: We should be able to make this generic over a `Metric`.
    pub fn generate_random_node_id(target_bucket_idx: u8, local_node_id: NodeId) -> NodeId {
        let distance_leading_zeroes = 255 - target_bucket_idx;
        let random_distance = trin_utils::bytes::random_32byte_array(distance_leading_zeroes);

        let raw_node_id = XorMetric::distance(&local_node_id.raw(), &random_distance);

        let raw_bytes = raw_node_id.big_endian();

        raw_bytes.into()
    }
}

impl From<RawNodeId> for NodeId {
    fn from(item: RawNodeId) -> Self {
        NodeId(item)
    }
}

impl From<EnrNodeId> for NodeId {
    fn from(value: EnrNodeId) -> Self {
        NodeId(value.raw())
    }
}

impl From<NodeId> for EnrNodeId {
    fn from(val: NodeId) -> Self {
        EnrNodeId::new(val.deref())
    }
}

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

impl Deref for NodeId {
    type Target = RawNodeId;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use crate::trin_types::enr::Enr;
    use crate::trin_types::node_id::NodeId;
    use std::net::Ipv4Addr;

    #[test]
    fn test_enr_ser_de() {
        let enr_base64 = r#""enr:-I24QAnHRBtPxxqnrZ0A9Xw1GV0cr3g178FcLutgd1DcG8a1FjOoRooOleI79K2NvTXYpOpkbe_NN-VqNZqS2a_Bo40BY4d0IDAuMS4wgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQIJSs6oF8rPca9GjRV6tNaJ2YfZb5nNQjui2VUloBleH4N1ZHCCIyo""#;
        let expected_node_id = [
            176, 202, 35, 254, 68, 245, 224, 61, 174, 106, 81, 237, 41, 88, 144, 15, 55, 58, 125,
            119, 228, 39, 201, 211, 154, 95, 148, 198, 212, 185, 175, 219,
        ];
        let expected_ip4 = Some(Ipv4Addr::from([127, 0, 0, 1]));

        let enr: Enr = serde_json::from_str(enr_base64).unwrap();
        assert_eq!(enr.node_id(), expected_node_id);
        assert_eq!(enr.ip4(), expected_ip4);

        let decoded_enr = serde_json::to_string(&enr).unwrap();
        assert_eq!(decoded_enr, enr_base64);
    }

    #[test]
    fn test_node_id_ser_de() {
        let node_id = NodeId([
            176, 202, 35, 254, 68, 245, 224, 61, 174, 106, 81, 237, 41, 88, 144, 15, 55, 58, 125,
            119, 228, 39, 201, 211, 154, 95, 148, 198, 212, 185, 175, 219,
        ]);

        let node_id_string = serde_json::to_string(&node_id).unwrap();

        assert_eq!(node_id, serde_json::from_str(&node_id_string).unwrap());
    }
}
