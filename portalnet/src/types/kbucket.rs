use std::{collections::HashMap, sync::Arc};

use discv5::{
    enr::NodeId,
    kbucket::{
        AppliedPending, Entry as KBucketEntry, InsertResult, KBucketsTable, NodeStatus,
        UpdateResult,
    },
    ConnectionDirection, ConnectionState, Enr, Key,
};
use ethportal_api::types::distance::{Distance, Metric};
use itertools::Itertools;
use parking_lot::RwLock;
use tracing::debug;

use super::node::Node;

/// Information regarding single entry in the routing table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// The entry is present in a bucket.
    Present(Node, NodeStatus),
    /// The entry is pending insertion in a bucket.
    Pending(Node, NodeStatus),
    /// The entry is absent and may be inserted.
    Absent,
    /// The entry represents the local node.
    SelfEntry,
}

impl Entry {
    /// Returns node if present, None otherwise.
    pub fn present(self) -> Option<Node> {
        match self {
            Entry::Present(node, _node_status) => Some(node),
            _ => None,
        }
    }

    /// Returns node if present or pending, None otherwise.
    pub fn present_or_pending(self) -> Option<Node> {
        match self {
            Entry::Present(node, _node_status) | Entry::Pending(node, _node_status) => Some(node),
            Entry::Absent | Entry::SelfEntry => None,
        }
    }
}

impl From<KBucketEntry<'_, NodeId, Node>> for Entry {
    fn from(bucket: KBucketEntry<'_, NodeId, Node>) -> Self {
        match bucket {
            KBucketEntry::Present(entry, node_status) => {
                Self::Present(entry.value().clone(), node_status)
            }
            KBucketEntry::Pending(mut entry, node_status) => {
                Self::Pending(entry.value().clone(), node_status)
            }
            KBucketEntry::Absent(_entry) => Self::Absent,
            KBucketEntry::SelfEntry => Self::SelfEntry,
        }
    }
}

/// The result of the [SharedKBucketsTable::insert_or_update_discovered_nodes] function.
///
/// Contains node ids of nodes that were either inserted into or removed from routing table.
#[derive(Default)]
pub struct DiscoveredNodesUpdateResult {
    pub inserted_nodes: Vec<NodeId>,
    pub removed_nodes: Vec<NodeId>,
}

/// The wrapper around [`discv5::kbucket::KBucketsTable`] that is safe for async usage.
///
/// Every function holds the lock only for the duration of the function, and no other blocking
/// calls are made during that time.
#[derive(Clone)]
pub struct SharedKBucketsTable {
    kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
}

impl SharedKBucketsTable {
    pub fn new(kbuckets: KBucketsTable<NodeId, Node>) -> Self {
        Self {
            kbuckets: Arc::new(RwLock::new(kbuckets)),
        }
    }

    /// Returns an `Entry` for the given key, representing the state of the entry
    /// in the routing table.
    pub fn entry(&self, node_id: NodeId) -> Entry {
        self.kbuckets.write().entry(&Key::from(node_id)).into()
    }

    /// Removes a node from the routing table. Returns `true` of the node existed.
    pub fn remove(&self, node_id: NodeId) -> bool {
        self.kbuckets.write().remove(&Key::from(node_id))
    }

    /// Updates a node's value if it exists in the table.
    ///
    /// Optionally the connection state can be modified.
    pub fn update_node(&self, node: Node, state: Option<ConnectionState>) -> UpdateResult {
        let key = Key::from(node.enr.node_id());
        self.kbuckets.write().update_node(&key, node, state)
    }

    /// Updates a node's status if it exists in the table.
    ///
    /// This checks all table and bucket filters before performing the update.
    pub fn update_node_status(
        &self,
        node_id: NodeId,
        state: ConnectionState,
        direction: Option<ConnectionDirection>,
    ) -> UpdateResult {
        self.kbuckets
            .write()
            .update_node_status(&Key::from(node_id), state, direction)
    }

    /// Attempts to insert or update in the routing table.
    pub fn insert_or_update(&self, node: Node, node_status: NodeStatus) -> InsertResult<NodeId> {
        let key = Key::from(node.enr.node_id());
        self.kbuckets
            .write()
            .insert_or_update(&key, node, node_status)
    }

    /// Inserts or updates discovered nodes.
    ///
    /// If node is already in the routing table and provided enr is newer, updates the node.
    /// If node is not in the routing table, insert it with max distance and as disconnected.
    pub fn insert_or_update_discovered_nodes(
        &self,
        enrs: impl IntoIterator<Item = Enr>,
    ) -> DiscoveredNodesUpdateResult {
        let mut result = DiscoveredNodesUpdateResult::default();

        // Acquire write lock here so that we can perform everything atomically.
        let mut kbuckets = self.kbuckets.write();

        for enr in enrs {
            let node_id = enr.node_id();

            let key = Key::from(node_id);

            // If the node is in the routing table, then check to see if we should update its entry.
            // If the node is not in the routing table, then insert the node in a disconnected state
            // (a subsequent ping will establish connectivity with the node). Ignore insertion
            // failures.
            if let Some(node) = Entry::from(kbuckets.entry(&key)).present_or_pending() {
                if node.enr.seq() < enr.seq() {
                    let node = Node::new(enr, node.data_radius());

                    if let UpdateResult::Failed(reason) = kbuckets.update_node(&key, node, None) {
                        // The update removed the node because it would violate the incoming peers
                        // condition or a bucket/table filter.
                        result.removed_nodes.push(node_id);
                        debug!(
                            peer = %node_id,
                            error = ?reason,
                            "Error updating entry for discovered node",
                        );
                    }
                }
            } else {
                let node = Node::new(enr, Distance::MAX);
                let status = NodeStatus {
                    state: ConnectionState::Disconnected,
                    direction: ConnectionDirection::Outgoing,
                };
                match kbuckets.insert_or_update(&key, node, status) {
                    InsertResult::Inserted => {
                        debug!(inserted = %node_id, "Discovered node inserted into routing table");
                        result.inserted_nodes.push(node_id);
                    }
                    other => {
                        debug!(
                            peer = %node_id,
                            reason = ?other,
                            "Discovered node not inserted into routing table"
                        );
                    }
                }
            }
        }

        result
    }

    /// Returns the number of buckets in the routing table.
    ///
    /// With the current implementation, this should be 256.
    pub fn buckets_count(&self) -> usize {
        self.kbuckets.read().buckets_iter().count()
    }

    /// Returns up to `limit` connected nodes that are at any given log2 distances.
    ///
    /// We can't use [KBucketsTable::nodes_by_distances] to retrieve nodes from all distances
    /// because we filter out disconnected nodes afterwards, which can result in us returning less
    /// than desired number of nodes.
    pub fn nodes_by_distances(
        &self,
        local_enr: Enr,
        log2_distances: &[u16],
        limit: usize,
    ) -> Vec<Enr> {
        let mut result = vec![];

        for log2_distance in log2_distances.iter().sorted().dedup() {
            let log2_distance = *log2_distance as u64;

            // Add local node if distance is 0
            if log2_distance == 0 {
                result.push(local_enr.clone());
                continue;
            }

            for entry in self
                .kbuckets
                .write()
                .nodes_by_distances(&[log2_distance], limit)
            {
                // Filter out disconnected nodes.
                if !entry.status.is_connected() {
                    continue;
                }

                result.push(entry.node.value.enr());

                if result.len() >= limit {
                    // We reached the limit, exit early
                    return result;
                }
            }
        }

        result
    }

    /// Returns up to `limit` connected nodes that are closest to the given node id.
    pub fn closest_to_node_id(&self, target: NodeId, limit: usize) -> Vec<Enr> {
        let target_key = Key::from(target);
        self.kbuckets
            .write()
            .iter()
            // Filter out disconnected nodes.
            .filter(|entry| entry.status.is_connected())
            .map(|entry| entry.node)
            // Sort by distance
            .sorted_by_cached_key(|node| target_key.distance(node.key))
            .take(limit)
            .map(|node| node.value.enr())
            .collect()
    }

    /// Returns up to `limit` connected nodes that are closest to the given content id.
    pub fn closest_to_content_id<TMetric: Metric>(
        &self,
        content_id: &[u8; 32],
        limit: usize,
    ) -> Vec<Enr> {
        self.kbuckets
            .write()
            .iter()
            // Filter out disconnected nodes.
            .filter(|entry| entry.status.is_connected())
            .map(|entry| entry.node)
            // Sort by distance
            .sorted_by_cached_key(|node| TMetric::distance(content_id, &node.key.preimage().raw()))
            .take(limit)
            .map(|node| node.value.enr())
            .collect()
    }

    /// Returns all nodes that are connected and interested into provided content id.
    pub fn interested_enrs<TMetric: Metric>(&self, content_id: &[u8; 32]) -> Vec<Enr> {
        self.kbuckets
            .write()
            .iter()
            // Filter out disconnected nodes.
            .filter(|entry| entry.status.is_connected())
            .map(|entry| entry.node)
            // Keep only nodes that are interested in content
            .filter(|node| {
                TMetric::distance(content_id, &node.key.preimage().raw()) <= node.value.data_radius
            })
            .map(|node| node.value.enr())
            .collect()
    }

    /// For each content id, returns all ENRs that are connected and interested into it.
    ///
    /// The keys of the resulting map will always contain all `content_ids`. If none of the nodes is
    /// interested into specific content id, it will still be present in the result but the value
    /// associated with it will be empty.
    pub fn batch_interested_enrs<TMetric: Metric>(
        &self,
        content_ids: &[&[u8; 32]],
    ) -> HashMap<[u8; 32], Vec<Enr>> {
        let mut result = content_ids
            .iter()
            .map(|content_id| (**content_id, vec![]))
            .collect::<HashMap<_, _>>();
        for entry in self.kbuckets.write().iter() {
            // Skip non-connected nodes
            if !entry.status.is_connected() {
                continue;
            }
            let node = entry.node;
            for content_id in content_ids {
                let distance = TMetric::distance(content_id, &node.key.preimage().raw());
                if distance <= node.value.data_radius {
                    result
                        .entry(**content_id)
                        .or_default()
                        .push(node.value.enr());
                }
            }
        }
        result
    }

    /// Consumes the next applied pending entry, if any.
    ///
    /// See [KBucketsTable::take_applied_pending] for more info.
    pub fn take_applied_pending(&self) -> Option<AppliedPending<NodeId, Node>> {
        self.kbuckets.write().take_applied_pending()
    }

    /// Returns all ENRs in the routing table.
    ///
    /// Should be used only if all ENRs are desired.
    pub fn enrs(&self) -> Vec<Enr> {
        self.kbuckets
            .write()
            .iter()
            .map(|entry| entry.node.value.enr())
            .collect()
    }
}

impl From<&SharedKBucketsTable> for ethportal_api::KBucketsTable {
    fn from(shared_kbuckets: &SharedKBucketsTable) -> Self {
        let buckets = shared_kbuckets
            .kbuckets
            .read()
            .buckets_iter()
            .map(|bucket| ethportal_api::Bucket {
                node_ids: bucket.iter().map(|node| *node.key.preimage()).collect(),
            })
            .collect();
        Self { buckets }
    }
}
