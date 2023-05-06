use super::enr::Enr;
use super::node_id::NodeId;
use std::collections::HashMap;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use super::distance::{Metric, XorMetric};

type ContentId = NodeId;

/// Keeps track of query details.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct QueryTrace {
    /// None if the content was not found.
    pub received_content_from_node: Option<NodeId>,
    /// The local node.
    pub origin: NodeId,
    /// Map of a node's ID to its corresponding `QueryResponse`
    pub responses: HashMap<NodeId, QueryResponse>,
    pub node_metadata: HashMap<NodeId, NodeInfo>,
    started_at: SystemTime,
    target_id: ContentId,
}

impl QueryTrace {
    pub fn new(local_enr: &Enr, target_id: ContentId) -> Self {
        QueryTrace {
            received_content_from_node: None,
            origin: local_enr.into(),
            responses: HashMap::new(),
            node_metadata: HashMap::new(),
            started_at: SystemTime::now(),
            target_id,
        }
    }

    /// Records the receipt of a node as part of a query in the trace.
    /// Adds a new `QueryResponse` object for `node` if it does not exist, updates if it does.
    /// Timestamp for the object is only set on the first call for a given `node`.
    pub fn node_responded_with(&mut self, enr: &Enr, responded_with: Vec<&Enr>) {
        let node_id = enr.into();
        let mut responded_with_ids: Vec<NodeId> = responded_with
            .into_iter()
            .map(|received_enr| {
                self.add_node_metadata(received_enr, false);
                received_enr.into()
            })
            .collect();
        self.responses
            .entry(node_id)
            .or_insert_with(|| {
                // Entry does not exist, create it and insert it.
                let timestamp_u64 = QueryTrace::timestamp_millis_u64(self.started_at);
                QueryResponse {
                    timestamp_millis: timestamp_u64,
                    responded_with: vec![],
                }
            })
            .responded_with
            .append(&mut responded_with_ids);
        self.add_node_metadata(enr, true);
    }

    /// Mark the node that responded with the content, and when it was received.
    pub fn node_responded_with_content(&mut self, enr: &Enr) {
        let node_id = enr.into();
        self.received_content_from_node = Some(node_id);
        let timestamp_u64 = QueryTrace::timestamp_millis_u64(self.started_at);
        self.responses.insert(
            node_id,
            QueryResponse {
                timestamp_millis: timestamp_u64,
                responded_with: vec![],
            },
        );
        self.add_node_metadata(enr, true);
    }

    /// Returns milliseconds since the time provided.
    fn timestamp_millis_u64(since: SystemTime) -> u64 {
        let timestamp_millis_u128 = SystemTime::now()
            .duration_since(since)
            .unwrap_or_default()
            .as_millis();
        // JSON serialization does not support u128. u64 can hold a few million years worth of milliseconds.
        u64::try_from(timestamp_millis_u128).unwrap_or(u64::MAX)
    }

    fn add_node_metadata(&mut self, enr: &Enr, node_responded: bool) {
        let target = self.target_id;
        self.node_metadata
            .entry(enr.into())
            .and_modify(|node_info| {
                // If we see a different ENR for a Node ID we've already seen,
                // use the newer ENR if its seq # is higher. If the seq #s are equal
                // use the ENR that we received a response from.
                let different_enr: bool = *enr != node_info.enr;
                let higher_incoming_seq_number: bool = enr.seq() > node_info.enr.seq();
                let same_incoming_seq_number: bool = enr.seq() == node_info.enr.seq();
                if different_enr
                    && ((same_incoming_seq_number && node_responded) || higher_incoming_seq_number)
                {
                    *node_info = QueryTrace::get_node_metadata(enr, &target);
                }
            })
            .or_insert_with(|| -> NodeInfo { QueryTrace::get_node_metadata(enr, &target) });
    }

    fn get_node_metadata(enr: &Enr, target: &ContentId) -> NodeInfo {
        let node_id = enr.node_id();
        let node_id_raw = node_id.raw();
        let ip = match enr.ip4() {
            Some(ip) => ip.to_string(),
            None => "".to_owned(),
        };
        let port = enr.udp4().unwrap_or(0).to_string();
        let distance = XorMetric::distance(&node_id_raw, &target.raw());
        let distance_log2 = distance.log2().unwrap_or(0);
        let distance: u64 = distance.0[3];
        let distance = (distance >> 32) as u32;

        NodeInfo {
            enr: enr.clone(),
            ip,
            port,
            distance_to_content: distance,
            distance_log2,
        }
    }
}

/// Represents the response from a single node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryResponse {
    /// Milliseconds since query started.
    pub timestamp_millis: u64,
    /// Node IDs that this node responded with.
    pub responded_with: Vec<NodeId>,
}

/// Represents additional info for a given node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInfo {
    pub enr: Enr,
    pub ip: String,
    pub port: String,
    pub distance_to_content: u32,
    pub distance_log2: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::trin_types::enr::generate_random_remote_enr;

    #[test]
    fn test_query_trace() {
        let (_, local_enr) = generate_random_remote_enr();
        let local_node_id = &local_enr.node_id().into();

        let mut tracer = QueryTrace::new(&local_enr, local_enr.node_id().into());
        let (_, enr_a) = generate_random_remote_enr();
        let node_id_a: &NodeId = &enr_a.clone().into();
        let (_, enr_b) = generate_random_remote_enr();
        let node_id_b = &enr_b.clone().into();
        let (_, enr_c) = generate_random_remote_enr();
        let node_id_c = &enr_c.clone().into();

        tracer.node_responded_with(&local_enr, vec![&enr_a.clone()]);
        tracer.node_responded_with(&local_enr, vec![&enr_b.clone()]);
        tracer.node_responded_with(&local_enr, vec![&enr_c]);

        let (_, enr_d) = generate_random_remote_enr();
        let node_id_d = &enr_d.node_id().into();

        tracer.node_responded_with(&enr_a, vec![]);
        tracer.node_responded_with(&enr_b, vec![&enr_d]);
        tracer.node_responded_with_content(&enr_c);

        let origin_entry = tracer.responses.get(local_node_id).unwrap();

        // check that entry for origin contains a, b, c
        assert!(origin_entry.responded_with.contains(node_id_a));
        assert!(origin_entry.responded_with.contains(node_id_b));
        assert!(origin_entry.responded_with.contains(node_id_c));

        // check that entry for a contains empty list
        let a_entry = tracer.responses.get(node_id_a).unwrap();
        assert!(a_entry.responded_with.is_empty());
        // check that entry for b contains d
        let b_entry = tracer.responses.get(node_id_b).unwrap();
        assert!(b_entry.responded_with.contains(node_id_d));
        // check that content_received_from_node is c
        let c_entry = tracer.responses.get(node_id_c).unwrap();
        assert!(c_entry.responded_with.is_empty());
        assert_eq!(tracer.received_content_from_node, Some(*node_id_c));

        // check node metatdata
        let a_data = tracer.node_metadata.get(node_id_a).unwrap();
        assert_eq!(a_data.enr, enr_a);
        let b_data = tracer.node_metadata.get(node_id_b).unwrap();
        assert_eq!(b_data.enr, enr_b);
        let c_data = tracer.node_metadata.get(node_id_c).unwrap();
        assert_eq!(c_data.enr, enr_c);
        let d_data = tracer.node_metadata.get(node_id_d).unwrap();
        assert_eq!(d_data.enr, enr_d);
        let local_data = tracer.node_metadata.get(local_node_id).unwrap();
        assert_eq!(local_data.enr, local_enr);
    }
}
