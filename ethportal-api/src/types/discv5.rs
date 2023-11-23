use super::enr::Enr;
use crate::utils::bytes::hex_encode;
use serde::{Deserialize, Serialize};

use discv5::enr::NodeId;

/// Discv5 bucket
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Bucket {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub node_ids: Vec<String>,
}

/// Represents a discv5 kbuckets table
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KBucketsTable {
    pub buckets: Vec<Bucket>,
}

/// Discv5 node information
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfo {
    pub enr: Enr,
    pub node_id: String,
    pub ip: Option<String>,
}

/// Information about a discv5/overlay network's routing table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutingTableInfo {
    pub local_node_id: String,
    pub buckets: KBucketsTable,
}

impl<TVal: Eq> From<discv5::kbucket::KBucketsTable<NodeId, TVal>> for KBucketsTable {
    fn from(table: discv5::kbucket::KBucketsTable<NodeId, TVal>) -> Self {
        let buckets = table
            .buckets_iter()
            .map(|bucket| Bucket {
                node_ids: bucket
                    .iter()
                    .map(|node| hex_encode(*node.key.preimage()))
                    .collect(),
            })
            .collect();

        KBucketsTable { buckets }
    }
}
