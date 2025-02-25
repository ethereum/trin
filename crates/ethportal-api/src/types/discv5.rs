use std::net::IpAddr;

use discv5::{enr::NodeId, service::Pong as Discv5Pong};
use serde::{Deserialize, Serialize};

use super::enr::Enr;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pong {
    pub enr_seq: u64,
    pub ip: IpAddr,
    pub port: u16,
}

impl From<Discv5Pong> for Pong {
    fn from(value: Discv5Pong) -> Self {
        let Discv5Pong { enr_seq, ip, port } = value;
        Self { enr_seq, ip, port }
    }
}

/// Discv5 bucket
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Bucket {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub node_ids: Vec<NodeId>,
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
    pub node_id: NodeId,
    pub ip: Option<String>,
}

/// Information about a discv5/overlay network's routing table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutingTableInfo {
    pub local_node_id: NodeId,
    pub buckets: KBucketsTable,
}

impl<TVal: Eq> From<discv5::kbucket::KBucketsTable<NodeId, TVal>> for KBucketsTable {
    fn from(table: discv5::kbucket::KBucketsTable<NodeId, TVal>) -> Self {
        let buckets = table
            .buckets_iter()
            .map(|bucket| Bucket {
                node_ids: bucket.iter().map(|node| *node.key.preimage()).collect(),
            })
            .collect();

        KBucketsTable { buckets }
    }
}
