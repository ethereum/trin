use crate::enr::Enr;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::node_id::NodeId;

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
    pub ip: Option<String>,
}

pub type RoutingTableInfo = Value;
