use crate::portalnet::Enr;
use discv5::{
    enr::NodeId,
    kbucket::{ConnectionState, NodeStatus},
};
use ethereum_types::U256;
use serde_json::{json, Value};
use std::collections::BTreeMap;

type NodeMap = BTreeMap<String, String>;
type NodeTuple = (usize, NodeId, Enr, NodeStatus, U256);

/// Converts the output of the Overlay's bucket_entries method to a JSON Value
pub fn bucket_entries_to_json(bucket_entries: Vec<NodeTuple>) -> Value {
    let mut node_count: u16 = 0;
    let mut connected_count: u16 = 0;
    let nodes_indexed: Vec<NodeMap> = bucket_entries
        .into_iter()
        .map(|(bucket_index, node_id, enr, node_status, data_radius)| {
            node_count += 1;
            if node_status.state == ConnectionState::Connected {
                connected_count += 1
            }
            let mut map = BTreeMap::new();
            map.insert("bucket".to_owned(), format!("{}", bucket_index));
            map.insert(
                "node_id".to_owned(),
                format!("0x{}", hex::encode(node_id.raw())),
            );
            map.insert("enr".to_owned(), enr.to_base64());
            map.insert("status".to_owned(), format!("{:?}", node_status.state));
            map.insert("radius".to_owned(), format!("{}", data_radius));
            map
        })
        .collect();

    json!(
        {
            "nodes": nodes_indexed,
            "numNodes": node_count,
            "numConnected": connected_count
        }
    )
}
