use std::{
    collections::HashMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::primitives::B256;
use discv5::enr::NodeId;
use serde::{Deserialize, Serialize};

use super::{
    distance::{Metric, XorMetric},
    enr::Enr,
};

type ContentId = B256;

/// Keeps track of query details.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct QueryTrace {
    /// Node ID from which the content was received. None if the content was not found & verified.
    pub received_from: Option<NodeId>,
    /// The local node.
    pub origin: NodeId,
    /// Map of a node's ID to its corresponding `QueryResponse`
    pub responses: HashMap<NodeId, QueryResponse>,
    /// Track if and how each node fails during a query
    pub failures: HashMap<NodeId, QueryFailure>,
    /// Contains a map from node ID to the metadata object for that node.
    pub metadata: HashMap<NodeId, NodeInfo>,
    /// Timestamp when the query was started.
    pub started_at_ms: u64,
    /// Target content ID
    pub target_id: ContentId,
    /// List of pending requests that were unresolved when the content was found.
    pub cancelled: Vec<NodeId>,
}

impl QueryTrace {
    pub fn new(local_enr: &Enr, target_id: ContentId) -> Self {
        let started_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        // Convert to u64, as JSON serialization does not support u128.
        let started_at_ms = u64::try_from(started_at_ms).unwrap_or(u64::MAX);

        QueryTrace {
            received_from: None,
            origin: local_enr.into(),
            responses: HashMap::new(),
            failures: HashMap::new(),
            metadata: HashMap::new(),
            started_at_ms,
            cancelled: Vec::new(),
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
                self.add_metadata(received_enr, false);
                received_enr.into()
            })
            .collect();
        self.responses
            .entry(node_id)
            .or_insert_with(|| {
                // Entry does not exist, create it and insert it.
                let timestamp_u64 = QueryTrace::timestamp_millis_u64(self.started_at_ms);
                QueryResponse {
                    duration_ms: timestamp_u64,
                    responded_with: vec![],
                }
            })
            .responded_with
            .append(&mut responded_with_ids);
        self.add_metadata(enr, true);
    }

    /// Mark that a node responded with content, and when it was received.
    /// Multiple nodes might respond, for a variety of reasons, including:
    /// - they sent content that was later invalidated
    /// - they claimed to have content for utp transfer, but disappeared before transmission
    /// - they sent content too slowly, and we found it elsewhere
    pub fn node_responded_with_content(&mut self, enr: &Enr) {
        let node_id = enr.into();
        let timestamp_u64 = QueryTrace::timestamp_millis_u64(self.started_at_ms);
        self.responses.insert(
            node_id,
            QueryResponse {
                duration_ms: timestamp_u64,
                responded_with: vec![],
            },
        );
        self.add_metadata(enr, true);
    }

    /// Mark that we have removed a node from the query, for invalid behavior.
    pub fn node_failed(&mut self, node_id: NodeId, failure: QueryFailureKind) {
        let timestamp_u64 = QueryTrace::timestamp_millis_u64(self.started_at_ms);
        self.failures.insert(
            node_id,
            QueryFailure {
                duration_ms: timestamp_u64,
                failure,
            },
        );
    }

    /// Mark the node that sent the content that was finally verified.
    pub fn content_validated(&mut self, node_id: NodeId) {
        if self.received_from.is_none() {
            self.received_from = Some(node_id);
        }
    }

    /// Returns milliseconds since the time provided.
    fn timestamp_millis_u64(since: u64) -> u64 {
        // Convert `since` (milliseconds) to a `SystemTime`
        let since_time = UNIX_EPOCH + Duration::from_millis(since);

        let timestamp_millis_u128 = SystemTime::now()
            .duration_since(since_time)
            .unwrap_or_default()
            .as_millis();

        // JSON serialization does not support u128. u64 can hold a few million years worth of
        // milliseconds.
        u64::try_from(timestamp_millis_u128).unwrap_or(u64::MAX)
    }

    fn add_metadata(&mut self, enr: &Enr, node_responded: bool) {
        let target = self.target_id;
        self.metadata
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
                    *node_info = QueryTrace::get_metadata(enr, &target);
                }
            })
            .or_insert_with(|| -> NodeInfo { QueryTrace::get_metadata(enr, &target) });
    }

    fn get_metadata(enr: &Enr, target: &ContentId) -> NodeInfo {
        let node_id = enr.node_id();
        let node_id_raw = node_id.raw();
        let distance = XorMetric::distance(&node_id_raw, target);
        let distance = distance.big_endian().into();
        NodeInfo {
            enr: enr.clone(),
            distance,
            radius: None,
        }
    }
}

/// Represents the response from a single node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryResponse {
    /// Milliseconds since query started.
    pub duration_ms: u64,
    /// Node IDs that this node responded with.
    pub responded_with: Vec<NodeId>,
}

/// Represents a fatal failure of a single node during a query.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryFailure {
    /// Milliseconds since query started.
    pub duration_ms: u64,
    /// Way in which the node failed.
    pub failure: QueryFailureKind,
}

/// Represents the kind of failure a node experienced during a query.
///
/// These do not include the case where a node does not respond at all, or behaves in an
/// undesirable but recoverable way. This only includes fatal failures that cause us to immediately
/// stop querying the node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum QueryFailureKind {
    /// The uTP connection to the node failed.
    UtpConnectionFailed,
    /// The uTP transfer from the node failed.
    UtpTransferFailed,
    /// The node fully sent content, but the content was invalid.
    InvalidContent,
}

/// Represents additional info for a given node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfo {
    pub enr: Enr,
    pub distance: B256,
    pub radius: Option<B256>,
}

#[cfg(test)]
mod tests {
    use alloy::primitives::U256;
    use serde_json::{json, Value};

    use super::*;
    use crate::types::enr::generate_random_remote_enr;

    fn new_node() -> (NodeId, Enr) {
        let (_, enr) = generate_random_remote_enr();
        let node_id = enr.node_id();
        (node_id, enr)
    }

    #[test]
    fn test_query_trace() {
        let (local_node_id, local_enr) = new_node();
        let mut tracer = QueryTrace::new(&local_enr, B256::from(local_enr.node_id().raw()));
        let (node_id_a, enr_a) = new_node();
        let (node_id_b, enr_b) = new_node();
        let (node_id_c, enr_c) = new_node();

        tracer.node_responded_with(&local_enr, vec![&enr_a.clone()]);
        tracer.node_responded_with(&local_enr, vec![&enr_b.clone()]);
        tracer.node_responded_with(&local_enr, vec![&enr_c]);

        let (node_id_d, enr_d) = new_node();

        tracer.node_responded_with(&enr_a, vec![]);
        tracer.node_responded_with(&enr_b, vec![&enr_d]);
        tracer.node_responded_with_content(&enr_c);
        tracer.content_validated(node_id_c);

        let origin_entry = tracer.responses.get(&local_node_id).unwrap();

        // check that entry for origin contains a, b, c
        assert!(origin_entry.responded_with.contains(&node_id_a));
        assert!(origin_entry.responded_with.contains(&node_id_b));
        assert!(origin_entry.responded_with.contains(&node_id_c));

        // check that entry for a contains empty list
        let a_entry = tracer.responses.get(&node_id_a).unwrap();
        assert!(a_entry.responded_with.is_empty());
        // check that entry for b contains d
        let b_entry = tracer.responses.get(&node_id_b).unwrap();
        assert!(b_entry.responded_with.contains(&node_id_d));
        // check that content_received_from_node is c
        let c_entry = tracer.responses.get(&node_id_c).unwrap();
        assert!(c_entry.responded_with.is_empty());
        assert_eq!(tracer.received_from, Some(node_id_c));

        // check node metadata
        let a_data = tracer.metadata.get(&node_id_a).unwrap();
        assert_eq!(a_data.enr, enr_a);
        let b_data = tracer.metadata.get(&node_id_b).unwrap();
        assert_eq!(b_data.enr, enr_b);
        let c_data = tracer.metadata.get(&node_id_c).unwrap();
        assert_eq!(c_data.enr, enr_c);
        let d_data = tracer.metadata.get(&node_id_d).unwrap();
        assert_eq!(d_data.enr, enr_d);
        let local_data = tracer.metadata.get(&local_node_id).unwrap();
        assert_eq!(local_data.enr, local_enr);
    }

    #[test]
    fn test_query_trace_multiple_peers() {
        let (local_node_id, local_enr) = new_node();
        let mut tracer = QueryTrace::new(&local_enr, B256::from(local_enr.node_id().raw()));
        let (node_id_a, enr_a) = new_node();
        let (node_id_b, enr_b) = new_node();
        let (node_id_c, enr_c) = new_node();

        tracer.node_responded_with(&local_enr, vec![&enr_a.clone(), &enr_b.clone(), &enr_c]);

        let origin_entry = tracer.responses.get(&local_node_id).unwrap();

        // check that entry for origin contains a, b, c
        assert!(origin_entry.responded_with.contains(&node_id_a));
        assert!(origin_entry.responded_with.contains(&node_id_b));
        assert!(origin_entry.responded_with.contains(&node_id_c));
    }

    #[test]
    fn test_query_trace_failures() {
        let (_, local_enr) = generate_random_remote_enr();
        let mut tracer = QueryTrace::new(&local_enr, B256::from(local_enr.node_id().raw()));
        let (node_id_a, enr_a) = new_node();
        let (node_id_b, enr_b) = new_node();
        let (node_id_c, enr_c) = new_node();

        tracer.node_responded_with(&local_enr, vec![&enr_a.clone(), &enr_b.clone(), &enr_c]);

        let (node_id_d, enr_d) = new_node();
        let (node_id_e, enr_e) = new_node();

        tracer.node_responded_with_content(&enr_a);
        tracer.node_failed(node_id_a, QueryFailureKind::UtpConnectionFailed);
        tracer.node_responded_with(&enr_b, vec![&enr_d, &enr_e]);
        tracer.node_responded_with_content(&enr_c);
        tracer.node_failed(node_id_c, QueryFailureKind::UtpTransferFailed);

        tracer.node_responded_with_content(&enr_d);
        tracer.node_failed(node_id_d, QueryFailureKind::InvalidContent);
        tracer.node_responded_with_content(&enr_e);
        tracer.content_validated(node_id_e);

        // check that entry for a contains empty list
        let a_entry = tracer.responses.get(&node_id_a).unwrap();
        assert!(a_entry.responded_with.is_empty());
        // check that entry for b contains d and e
        let b_entry = tracer.responses.get(&node_id_b).unwrap();
        assert!(b_entry.responded_with.contains(&node_id_d));
        assert!(b_entry.responded_with.contains(&node_id_e));
        // check that entry for c contains empty list
        let c_entry = tracer.responses.get(&node_id_c).unwrap();
        assert!(c_entry.responded_with.is_empty());
        // check that entry for d contains empty list
        let d_entry = tracer.responses.get(&node_id_d).unwrap();
        assert!(d_entry.responded_with.is_empty());
        // check that content_received_from_node is e
        let e_entry = tracer.responses.get(&node_id_e).unwrap();
        assert!(e_entry.responded_with.is_empty());
        assert_eq!(tracer.received_from, Some(node_id_e));

        // check for failures
        assert_eq!(tracer.failures.len(), 3);
        assert_eq!(
            tracer.failures.get(&node_id_a).unwrap().failure,
            QueryFailureKind::UtpConnectionFailed
        );
        assert_eq!(
            tracer.failures.get(&node_id_c).unwrap().failure,
            QueryFailureKind::UtpTransferFailed
        );
        assert_eq!(
            tracer.failures.get(&node_id_d).unwrap().failure,
            QueryFailureKind::InvalidContent
        );
    }

    #[test]
    fn test_target_id_encodes_correctly() {
        let (_, local_enr) = generate_random_remote_enr();
        let target_id = B256::from([0; 32]);
        let tracer = QueryTrace::new(&local_enr, target_id);
        let json_tracer: Value = json!(&tracer);
        assert_eq!(
            json_tracer["targetId"],
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        );
        let target_id = B256::from([1; 32]);
        let tracer = QueryTrace::new(&local_enr, target_id);
        let json_tracer: Value = json!(&tracer);
        assert_eq!(
            json_tracer["targetId"],
            "0x0101010101010101010101010101010101010101010101010101010101010101"
        );
        let target_id = B256::from(U256::from(2242405));
        let tracer = QueryTrace::new(&local_enr, target_id);
        let json_tracer: Value = json!(&tracer);
        assert_eq!(
            json_tracer["targetId"],
            "0x0000000000000000000000000000000000000000000000000000000000223765"
        );
    }

    #[rstest::rstest]
    #[case(5)]
    #[case(534543)]
    #[case(64574556345)]
    #[case(5435345345)]
    fn test_started_at_ms_time_is_serialized_to_json_properly(#[case] number: u64) {
        let (_, local_enr) = generate_random_remote_enr();
        let target_id = B256::ZERO;
        let mut tracer = QueryTrace::new(&local_enr, target_id);
        tracer.started_at_ms = number;
        let json_tracer: Value = json!(&tracer);
        assert_eq!(json_tracer["startedAtMs"], number);
    }
}
