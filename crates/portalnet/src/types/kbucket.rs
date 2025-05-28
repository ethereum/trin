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
use rand::{rng, seq::IteratorRandom};
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
            if let Some(mut node) = Entry::from(kbuckets.entry(&key)).present_or_pending() {
                if node.enr.seq() < enr.seq() {
                    node.set_enr(enr);
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
    /// We can't use [KBucketsTable::nodes_by_distances] to retrieve nodes from all distances in
    /// one call because we filter out disconnected nodes afterwards, which can result in us
    /// returning less than desired number of nodes.
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
                if result.len() >= limit {
                    // We reached the limit, exit early
                    return result;
                }
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

    /// Returns up to `limit` random connected nodes.
    pub fn random_peers(&self, limit: usize) -> Vec<Enr> {
        self.kbuckets
            .write()
            .iter()
            // Filter out disconnected nodes.
            .filter(|entry| entry.status.is_connected())
            .choose_multiple(&mut rng(), limit)
            .into_iter()
            .map(|entry| entry.node.value.enr())
            .collect()
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

    /// For each content id, returns all ENRs that are connected and interested into it.
    ///
    /// This function uses radius and distance to decides if peer is interested in content. If
    /// interest in content is not decided based on radius, then different function should be used
    /// instead.
    ///
    /// The keys of the resulting map will always contain all `content_ids`. If none of the nodes is
    /// interested into specific content id, it will still be present in the result but the value
    /// associated with it will be empty.
    pub fn batch_interested_enrs<'id, TMetric: Metric>(
        &self,
        content_ids: &[&'id [u8; 32]],
    ) -> HashMap<&'id [u8; 32], Vec<Enr>> {
        let mut result = content_ids
            .iter()
            .map(|&content_id| (content_id, vec![]))
            .collect::<HashMap<_, _>>();
        for entry in self.kbuckets.write().iter() {
            // Skip non-connected nodes
            if !entry.status.is_connected() {
                continue;
            }
            let node = entry.node;
            for &content_id in content_ids {
                let distance = TMetric::distance(content_id, &node.key.preimage().raw());
                if distance <= node.value.data_radius {
                    result.entry(content_id).or_default().push(node.value.enr());
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

// SharedKBucketsTable utility functions for testing purposes
#[cfg(test)]
impl SharedKBucketsTable {
    const MAX_INCOMING_PER_BUCKET: usize = 16;

    // 1 second is enough for testing purposes
    const PENDING_TIMEOUT_SEC: std::time::Duration = std::time::Duration::from_secs(1);

    const CONNECTED: NodeStatus = NodeStatus {
        state: ConnectionState::Connected,
        direction: ConnectionDirection::Outgoing,
    };
    const DISCONNECTED: NodeStatus = NodeStatus {
        state: ConnectionState::Disconnected,
        direction: ConnectionDirection::Outgoing,
    };

    pub fn new_for_tests(node_id: NodeId) -> Self {
        Self::new(KBucketsTable::new(
            Key::from(node_id),
            Self::PENDING_TIMEOUT_SEC,
            Self::MAX_INCOMING_PER_BUCKET,
            /* table_filter= */ None,
            /* bucket_filter= */ None,
        ))
    }

    pub fn insert_or_update_connected(
        &self,
        enr: &Enr,
        data_radius: Distance,
    ) -> InsertResult<NodeId> {
        self.insert_or_update(Node::new(enr.clone(), data_radius), Self::CONNECTED)
    }
    pub fn insert_or_update_disconnected(
        &self,
        enr: &Enr,
        data_radius: Distance,
    ) -> InsertResult<NodeId> {
        self.insert_or_update(Node::new(enr.clone(), data_radius), Self::DISCONNECTED)
    }
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;

    use discv5::{
        enr::CombinedKey,
        kbucket::{FailureReason, MAX_NODES_PER_BUCKET},
    };
    use ethportal_api::{generate_random_remote_enr, types::distance::XorMetric};
    use itertools::chain;

    use super::*;

    fn create_kbuckets_table() -> (Enr, SharedKBucketsTable) {
        let (_, local_enr) = generate_random_remote_enr();
        let kbuckets = SharedKBucketsTable::new_for_tests(local_enr.node_id());
        (local_enr, kbuckets)
    }

    fn generate_random_enr(node_id: impl AsRef<[u8]>, log2_distance: usize) -> Enr {
        generate_random_enr_with_key(node_id, log2_distance).1
    }

    fn generate_random_enr_with_key(
        node_id: impl AsRef<[u8]>,
        log2_distance: usize,
    ) -> (CombinedKey, Enr) {
        if !(250..=256).contains(&log2_distance) {
            panic!("log2_distance not in [250, 256] range");
        }
        let node_id = NodeId::parse(node_id.as_ref()).expect("Expected valid node id");
        loop {
            let (sk, enr) = generate_random_remote_enr();
            let distance = XorMetric::distance(&node_id.raw(), &enr.node_id().raw());
            if distance.log2() == Some(log2_distance) {
                return (sk, enr);
            }
        }
    }

    /// Asserts that two vectors of enr-s contain the same elements, not necessarily in order.
    fn assert_same_enrs(mut actual: Vec<Enr>, expected: Vec<Enr>) {
        assert_eq!(actual.len(), expected.len());
        for enr in expected {
            let index = actual
                .iter()
                .position(|a| a == &enr)
                .unwrap_or_else(|| panic!("Expected for {enr} to be in the list"));
            actual.remove(index);
        }
        assert!(actual.is_empty());
    }

    mod insert {
        use super::*;

        #[test]
        fn simple() {
            let (_local_enr, kbuckets) = create_kbuckets_table();

            let (_, enr) = generate_random_remote_enr();
            assert!(matches!(
                kbuckets.insert_or_update_connected(&enr, Distance::MAX),
                InsertResult::Inserted,
            ));

            assert!(kbuckets.entry(enr.node_id()).present().is_some());
        }

        #[test]
        fn full_bucket() {
            let (local_enr, kbuckets) = create_kbuckets_table();
            let local_node_id = local_enr.node_id();
            let log2_distance = 256;

            // Insert into bucket until full
            for _ in 0..MAX_NODES_PER_BUCKET {
                assert!(matches!(
                    kbuckets.insert_or_update_connected(
                        &generate_random_enr(local_node_id, log2_distance),
                        Distance::MAX
                    ),
                    InsertResult::Inserted,
                ));
            }

            let enr = generate_random_enr(local_node_id, log2_distance);

            // 1. Inserting connected node into bucket full of connected nodes should fail
            assert!(matches!(
                kbuckets.insert_or_update_connected(&enr, Distance::MAX),
                InsertResult::Failed(FailureReason::BucketFull),
            ));

            // 2. Change one node to disconnected
            let random_enr = kbuckets
                .nodes_by_distances(local_enr, &[log2_distance as u16], 1)
                .into_iter()
                .next()
                .unwrap();
            assert_eq!(
                kbuckets.update_node_status(
                    random_enr.node_id(),
                    ConnectionState::Disconnected,
                    None
                ),
                UpdateResult::Updated,
            );

            // 3. Inserting disconnected node into full bucket should fail
            assert!(matches!(
                kbuckets.insert_or_update_disconnected(&enr, Distance::MAX),
                InsertResult::Failed(FailureReason::BucketFull),
            ));

            // 4. Inserting connected node into full bucket should put it in pending
            assert!(matches!(
                kbuckets.insert_or_update_connected(&enr, Distance::MAX),
                InsertResult::Pending { .. },
            ));
            assert!(matches!(
                kbuckets.entry(enr.node_id()),
                Entry::Pending(_, _),
            ));

            // 5. Inserting connected node into full bucket with pending node should fail
            assert!(matches!(
                kbuckets.insert_or_update_connected(
                    &generate_random_enr(local_node_id, log2_distance),
                    Distance::MAX,
                ),
                InsertResult::Failed(FailureReason::BucketFull),
            ));

            // 6. Waiting PENDING_TIMEOUT_SEC should be enough to insert node_1 into bucket
            sleep(SharedKBucketsTable::PENDING_TIMEOUT_SEC);
            assert!(matches!(
                kbuckets.entry(enr.node_id()),
                Entry::Present(_, _)
            ));
        }
    }

    mod insert_or_update_discovered_nodes {
        use super::*;
        use crate::constants::DEFAULT_DISCOVERY_PORT;

        #[test]
        fn simple_insert_and_update() {
            let (local_enr, kbuckets) = create_kbuckets_table();

            // 1. Initialization - Prepare enrs

            let (secret_key_1, old_enr_1) = generate_random_remote_enr();
            let node_id_1 = old_enr_1.node_id();
            let mut new_enr_1 = old_enr_1.clone();
            new_enr_1
                .set_udp4(DEFAULT_DISCOVERY_PORT, &secret_key_1)
                .unwrap();

            let (secret_key_2, old_enr_2) = generate_random_remote_enr();
            let node_id_2 = old_enr_2.node_id();
            let mut new_enr_2 = old_enr_2.clone();
            new_enr_2
                .set_udp4(DEFAULT_DISCOVERY_PORT, &secret_key_2)
                .unwrap();

            let (_, enr_3) = generate_random_remote_enr();
            let node_id_3 = enr_3.node_id();

            // 2. Insert:
            // - local_enr - should be ignored
            // - old_enr_1 - should be inserted as disconnected
            // - new_enr_2 - should be inserted as disconnected
            let result = kbuckets.insert_or_update_discovered_nodes([
                local_enr,
                old_enr_1.clone(),
                new_enr_2.clone(),
            ]);
            assert_eq!(result.inserted_nodes, vec![node_id_1, node_id_2]);
            assert!(result.removed_nodes.is_empty());
            assert!(matches!(
                kbuckets.entry(node_id_1),
                Entry::Present(node, status) if node.enr == old_enr_1 && status == SharedKBucketsTable::DISCONNECTED,
            ));
            assert!(matches!(
                kbuckets.entry(node_id_2),
                Entry::Present(node, status) if node.enr == new_enr_2 && status == SharedKBucketsTable::DISCONNECTED,
            ));

            // 3. Update connection status of node_id_1
            assert_eq!(
                kbuckets.update_node_status(node_id_1, ConnectionState::Connected, None),
                UpdateResult::UpdatedAndPromoted,
            );
            assert!(matches!(
                kbuckets.entry(node_id_1),
                Entry::Present(node, status) if node.enr == old_enr_1 && status == SharedKBucketsTable::CONNECTED,
            ));

            // 4. Insert and Update:
            // - new_enr_1 - should be updated, and should stay connected
            // - old_new_2 - should not be updated
            // - enr_3 - should be inserted as disconnected
            let result = kbuckets.insert_or_update_discovered_nodes([
                new_enr_1.clone(),
                old_enr_2,
                enr_3.clone(),
            ]);
            assert_eq!(result.inserted_nodes, vec![node_id_3]);
            assert!(result.removed_nodes.is_empty());
            assert!(matches!(
                kbuckets.entry(node_id_1),
                Entry::Present(node, status) if node.enr == new_enr_1 && status == SharedKBucketsTable::CONNECTED,
            ));
            assert!(matches!(
                kbuckets.entry(node_id_2),
                Entry::Present(node, status) if node.enr == new_enr_2 && status == SharedKBucketsTable::DISCONNECTED,
            ));
            assert!(matches!(
                kbuckets.entry(node_id_3),
                Entry::Present(node, status) if node.enr == enr_3 && status == SharedKBucketsTable::DISCONNECTED,
            ));
        }

        #[test]
        fn full_bucket() {
            let (local_enr, kbuckets) = create_kbuckets_table();
            let local_node_id = local_enr.node_id();
            let log2_distance = 256;

            // Insert until bucket is full
            for _ in 0..MAX_NODES_PER_BUCKET {
                let enr_256 = generate_random_enr(local_node_id, log2_distance);
                let _ = kbuckets.insert_or_update_disconnected(&enr_256, Distance::ZERO);
            }

            // insert_or_update_discovered_nodes shouldn't do anything
            let enr = generate_random_enr(local_node_id, log2_distance);
            let result = kbuckets.insert_or_update_discovered_nodes([enr.clone()]);
            assert!(result.inserted_nodes.is_empty());
            assert!(result.removed_nodes.is_empty());
            assert!(matches!(kbuckets.entry(enr.node_id()), Entry::Absent));
        }

        #[test]
        fn pending() {
            let (local_enr, kbuckets) = create_kbuckets_table();
            let local_node_id = local_enr.node_id();
            let log2_distance = 256;

            // Insert until bucket is full
            for _ in 0..MAX_NODES_PER_BUCKET {
                let enr_256 = generate_random_enr(local_node_id, log2_distance);
                let _ = kbuckets.insert_or_update_disconnected(&enr_256, Distance::ZERO);
            }

            // Insert one node as pending
            let (secret_key, mut pending_enr) =
                generate_random_enr_with_key(local_node_id, log2_distance);
            assert!(matches!(
                kbuckets.insert_or_update_connected(&pending_enr, Distance::MAX),
                InsertResult::Pending { .. }
            ));

            // Check that pending node is updated
            pending_enr
                .set_udp4(DEFAULT_DISCOVERY_PORT, &secret_key)
                .unwrap();
            kbuckets.insert_or_update_discovered_nodes([pending_enr.clone()]);
            assert!(matches!(
                kbuckets.entry(pending_enr.node_id()),
                Entry::Pending(node, _) if node.enr == pending_enr,
            ));
        }
    }

    mod nodes_by_distances {
        use super::*;

        #[test]
        fn local() {
            let (local_enr, kbuckets) = create_kbuckets_table();
            assert_eq!(
                kbuckets.nodes_by_distances(local_enr.clone(), &[0], 10),
                vec![local_enr],
            );
        }

        #[test]
        fn closer_first() {
            let (local_enr, kbuckets) = create_kbuckets_table();
            let local_node_id = local_enr.node_id();

            let nodes_per_bucket = 5;

            // Add "nodes_per_bucket" nodes at distances 255 (closer) and 256 (farther)
            let closer_nodes = (0..nodes_per_bucket)
                .map(|_| generate_random_enr(local_node_id, 255))
                .collect_vec();
            let farther_nodes = (0..nodes_per_bucket)
                .map(|_| generate_random_enr(local_node_id, 256))
                .collect_vec();

            for enr in chain(&closer_nodes, &farther_nodes) {
                let _ = kbuckets.insert_or_update_connected(enr, Distance::MAX);
            }

            // Check that local node is always returned when distance 0 is present
            assert_eq!(
                kbuckets.nodes_by_distances(local_enr.clone(), &[256, 255, 0], /* limit= */ 1),
                vec![local_enr.clone()],
            );

            // Check that nodes_by_distances returns closer nodes even if farther distance is first
            // in argument
            assert_same_enrs(
                kbuckets.nodes_by_distances(local_enr.clone(), &[256, 255], nodes_per_bucket),
                closer_nodes,
            );

            // Check that only nodes that correspond to provided distance are returned
            assert_same_enrs(
                kbuckets.nodes_by_distances(local_enr, &[256], 2 * nodes_per_bucket),
                farther_nodes,
            );
        }

        #[test]
        fn only_connected() {
            let (local_enr, kbuckets) = create_kbuckets_table();
            let local_node_id = local_enr.node_id();

            let nodes_per_bucket = 5;

            // Insert closer nodes as disconnected
            let closer_nodes = (0..nodes_per_bucket)
                .map(|_| generate_random_enr(local_node_id, 255))
                .collect_vec();
            for enr in &closer_nodes {
                let _ = kbuckets.insert_or_update_disconnected(enr, Distance::MAX);
            }

            // Insert farther nodes as connected
            let farther_nodes = (0..nodes_per_bucket)
                .map(|_| generate_random_enr(local_node_id, 256))
                .collect_vec();
            for enr in &farther_nodes {
                let _ = kbuckets.insert_or_update_connected(enr, Distance::MAX);
            }

            // Check that only connected (farther) nodes are returned
            assert_same_enrs(
                kbuckets.nodes_by_distances(local_enr.clone(), &[255, 256], 2 * nodes_per_bucket),
                farther_nodes,
            );
        }
    }

    mod random {
        use super::*;

        #[test]
        fn simple() {
            let (_local_enr, kbuckets) = create_kbuckets_table();
            let content_id = NodeId::random().raw();

            let nodes_per_distance = 5;

            // Distance 254 and disconnected
            let enr_distance_254_disconnected = (0..nodes_per_distance)
                .map(|_| generate_random_enr(content_id, 254))
                .collect_vec();
            for enr in &enr_distance_254_disconnected {
                let _ = kbuckets.insert_or_update_disconnected(enr, Distance::MAX);
            }

            // Distances 255 and 256 and connected
            let enr_distance_255_connected = (0..nodes_per_distance)
                .map(|_| generate_random_enr(content_id, 255))
                .collect_vec();
            let enr_distance_256_connected = (0..nodes_per_distance)
                .map(|_| generate_random_enr(content_id, 256))
                .collect_vec();
            let all_connected = chain(&enr_distance_255_connected, &enr_distance_256_connected)
                .cloned()
                .collect_vec();

            for enr in &all_connected {
                let _ = kbuckets.insert_or_update_connected(enr, Distance::MAX);
            }

            // With high limit, all connected are returned
            assert_same_enrs(kbuckets.random_peers(3 * nodes_per_distance), all_connected);

            // With small limit, random up to limit are returned
            assert_eq!(
                kbuckets.random_peers(nodes_per_distance).len(),
                nodes_per_distance
            );
        }
    }

    mod closest {
        use super::*;

        #[test]
        fn closest_to_node_id() {
            let (_local_enr, kbuckets) = create_kbuckets_table();
            let target_node_id = NodeId::random();
            let nodes_per_distance = 5;

            // Distance 254 and disconnected
            let enr_distance_254_disconnected = (0..nodes_per_distance)
                .map(|_| generate_random_enr(target_node_id, 254))
                .collect_vec();
            for enr in &enr_distance_254_disconnected {
                let _ = kbuckets.insert_or_update_disconnected(enr, Distance::MAX);
            }

            // Distances 255 and 256 and connected
            let enr_distance_255_connected = (0..nodes_per_distance)
                .map(|_| generate_random_enr(target_node_id, 255))
                .collect_vec();
            let enr_distance_256_connected = (0..nodes_per_distance)
                .map(|_| generate_random_enr(target_node_id, 256))
                .collect_vec();
            let all_connected = chain(&enr_distance_255_connected, &enr_distance_256_connected)
                .cloned()
                .collect_vec();

            for enr in &all_connected {
                let _ = kbuckets.insert_or_update_connected(enr, Distance::MAX);
            }

            // With high limit, all connected are returned
            assert_same_enrs(
                kbuckets.closest_to_node_id(target_node_id, 3 * nodes_per_distance),
                all_connected,
            );

            // With small limit, closest are returned
            assert_same_enrs(
                kbuckets.closest_to_node_id(target_node_id, nodes_per_distance),
                enr_distance_255_connected,
            );
        }

        #[test]
        fn closest_to_content_id() {
            let (_local_enr, kbuckets) = create_kbuckets_table();
            let content_id = NodeId::random().raw();

            let nodes_per_distance = 5;

            // Distance 254 and disconnected
            let enr_distance_254_disconnected = (0..nodes_per_distance)
                .map(|_| generate_random_enr(content_id, 254))
                .collect_vec();
            for enr in &enr_distance_254_disconnected {
                let _ = kbuckets.insert_or_update_disconnected(enr, Distance::MAX);
            }

            // Distances 255 and 256 and connected
            let enr_distance_255_connected = (0..nodes_per_distance)
                .map(|_| generate_random_enr(content_id, 255))
                .collect_vec();
            let enr_distance_256_connected = (0..nodes_per_distance)
                .map(|_| generate_random_enr(content_id, 256))
                .collect_vec();
            let all_connected = chain(&enr_distance_255_connected, &enr_distance_256_connected)
                .cloned()
                .collect_vec();

            for enr in &all_connected {
                let _ = kbuckets.insert_or_update_connected(enr, Distance::MAX);
            }

            // With high limit, all connected are returned
            assert_same_enrs(
                kbuckets.closest_to_content_id::<XorMetric>(&content_id, 3 * nodes_per_distance),
                all_connected,
            );

            // With small limit, closest are returned
            assert_same_enrs(
                kbuckets.closest_to_content_id::<XorMetric>(&content_id, nodes_per_distance),
                enr_distance_255_connected,
            );
        }
    }

    mod interested_enrs {
        use alloy::primitives::U256;

        use super::*;

        #[test]
        fn batch() {
            let (_local_enr, kbuckets) = create_kbuckets_table();

            // Content ids
            let content_id_1 = NodeId::random().raw();
            let content_id_2 = generate_random_enr(content_id_1, 256).node_id().raw();

            // Node that should contain content_id_1 but not content_id_2
            let enr = generate_random_enr(content_id_1, 255);
            let half_max_distance = Distance::from(U256::MAX.wrapping_shr(1));
            let _ = kbuckets.insert_or_update_connected(&enr, half_max_distance);

            // Connected node with zero radius, shouldn't be returned
            let (_, enr_zero_connected) = generate_random_remote_enr();
            let _ = kbuckets.insert_or_update_connected(&enr_zero_connected, Distance::ZERO);

            // Disconnected node with max radius, shouldn't be returned
            let (_, enr_max_disconnected) = generate_random_remote_enr();
            let _ = kbuckets.insert_or_update_disconnected(&enr_max_disconnected, Distance::MAX);

            let mut result =
                kbuckets.batch_interested_enrs::<XorMetric>(&[&content_id_1, &content_id_2]);
            assert_eq!(result.len(), 2);
            assert_same_enrs(result.remove(&content_id_1).unwrap(), vec![enr.clone()]);
            assert_same_enrs(result.remove(&content_id_2).unwrap(), vec![]);

            // Add connected node with max radius, should always be returned
            let (_, enr_max_connected) = generate_random_remote_enr();
            let _ = kbuckets.insert_or_update_connected(&enr_max_connected, Distance::MAX);

            let mut result =
                kbuckets.batch_interested_enrs::<XorMetric>(&[&content_id_1, &content_id_2]);
            assert_eq!(result.len(), 2);
            assert_same_enrs(
                result.remove(&content_id_1).unwrap(),
                vec![enr, enr_max_connected.clone()],
            );
            assert_same_enrs(
                result.remove(&content_id_2).unwrap(),
                vec![enr_max_connected],
            );
        }
    }
}
