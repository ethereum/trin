use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use std::ops::Deref;
use serde_json::Value;

type RawNodeId = [u8; 32];

/// Discv5 NodeId
// TODO: Wrap this type over discv5::NodeId type
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeId(#[serde(with = "SerHex::<StrictPfx>")] pub RawNodeId);

impl From<RawNodeId> for NodeId {
    fn from(item: RawNodeId) -> Self {
        NodeId(item)
    }
}

impl Deref for NodeId {
    type Target = RawNodeId;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Node ENR
pub type Enr = enr::Enr<enr::CombinedKey>;

/// Discv5 bucket
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bucket {
    #[serde(flatten)]
    pub node_ids: Vec<NodeId>,
}

/// Represents a discv5 kbuckets table
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KBucketsTable {
    #[serde(flatten)]
    pub buckets: Vec<Bucket>,
}

/// Discv5 node information
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfo {
    pub enr: Enr,
    pub node_id: NodeId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
}

pub type RoutingTableInfo = Value;

#[cfg(test)]
mod test {
    use crate::types::discv5::{Enr, NodeId};
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
