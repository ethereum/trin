use crate::portalnet::Enr;
use discv5::{
    enr::NodeId,
    kbucket::{ConnectionState, NodeStatus},
};
use ethereum_types::U256;
use serde_json::{json, Value};
use std::collections::HashMap;

type NodeStringTuple = (String, String, String, String);
type NodeTuple = (NodeId, Enr, NodeStatus, U256);

pub fn bucket_entries_to_json(bucket_entries: HashMap<usize, Vec<NodeTuple>>) -> Value {
    let mut node_count: u16 = 0;
    let mut connected_count: u16 = 0;
    let buckets_indexed: HashMap<String, Vec<NodeStringTuple>> = bucket_entries
        .into_iter()
        .map(|(bucket_index, bucket)| {
            (
                format!("{}", bucket_index),
                bucket
                    .iter()
                    .map(|(node_id, enr, node_status, data_radius)| {
                        node_count += 1;
                        if node_status.state == ConnectionState::Connected {
                            connected_count += 1
                        }

                        (
                            format!("0x{}", hex::encode(node_id.raw())),
                            enr.to_base64(),
                            format!("{:?}", node_status.state),
                            format!("{}", data_radius),
                        )
                    })
                    .collect(),
            )
        })
        .collect();

    json!(
        {
            "buckets": buckets_indexed,
            "numBuckets": buckets_indexed.len(),
            "numNodes": node_count,
            "numConnected": connected_count
        }
    )
}
