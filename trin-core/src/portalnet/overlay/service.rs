use discv5::{
    enr::NodeId,
    kbucket::{
        self, ConnectionDirection, ConnectionState, FailureReason, InsertResult, KBucketsTable,
        NodeStatus, UpdateResult,
    },
};
use futures::{channel::oneshot, stream::StreamExt};
use log::{debug, warn};
use rocksdb::DB;
use std::sync::Arc;
use tokio::sync::{
    mpsc::{self, UnboundedReceiver, UnboundedSender},
    RwLock,
};

use crate::{
    portalnet::{
        discovery::Discovery,
        types::{
            FindContent, FindNodes, FoundContent, Message, Nodes, Ping, Pong, ProtocolKind,
            Request, Response, SszEnr,
        },
        Enr, U256,
    },
    utils::xor_two_values,
};

use super::hash_set_delay::HashSetDelay;

/// Maximum number of ENRs in response to FindNodes.
pub const FIND_NODES_MAX_NODES: usize = 32;
/// Maximum number of ENRs in response to FindContent.
pub const FIND_CONTENT_MAX_NODES: usize = 32;

/// An incoming or outgoing request.
#[derive(Debug)]
pub enum RequestDirection {
    Incoming { source: NodeId },
    Outgoing { destination: Enr },
}

/// A request to pass through the overlay.
#[derive(Debug)]
pub struct OverlayRequest {
    /// The request.
    pub request: Request,
    /// The direction of the request (incoming or outgoing).
    pub direction: RequestDirection,
    /// An optional responder to send a result of the request.
    /// The responder may be None if the request was initiated internally.
    pub responder: Option<oneshot::Sender<Result<Response, String>>>,
}

/// A node in the overlay network routing table.
#[derive(Clone)]
pub struct Node {
    /// The node's ENR.
    enr: Enr,
    /// The node's data radius.
    data_radius: U256,
}

impl Node {
    /// Returns the ENR of the node.
    pub fn enr(&self) -> Enr {
        self.enr.clone()
    }

    /// Returns the data radius of the node.
    pub fn data_radius(&self) -> U256 {
        self.data_radius.clone()
    }

    /// Sets the ENR of the node.
    pub fn set_enr(&mut self, enr: Enr) {
        self.enr = enr;
    }

    /// Sets the data radius of the node.
    pub fn set_data_radius(&mut self, radius: U256) {
        self.data_radius = radius;
    }
}

impl std::cmp::Eq for Node {}

impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        self.enr == other.enr
    }
}

/// The overlay service.
pub struct OverlayService {
    /// The underlying Discovery v5 protocol.
    discovery: Arc<RwLock<Discovery>>,
    /// The content database of the local node.
    db: Arc<DB>,
    /// The routing table of the local node.
    kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
    /// The data radius of the local node.
    data_radius: Arc<RwLock<U256>>,
    /// The protocol identifier.
    protocol: ProtocolKind,
    /// A queue of peers that require regular ping to check connectivity.
    peers_to_ping: HashSetDelay<NodeId>,
    /// The receiver half of a channel for service requests.
    request_rx: UnboundedReceiver<OverlayRequest>,
    /// The sender half of a channel for service requests.
    ///
    /// This is used internally to submit requests (e.g. maintenance ping requests).
    request_tx: UnboundedSender<OverlayRequest>,
}

impl OverlayService {
    /// Spawns the overlay network service.
    ///
    /// The state of the overlay network largely consists of its routing table. The routing table
    /// is updated according to incoming requests and responses as well as autonomous maintenance
    /// processes.
    pub async fn spawn(
        discovery: Arc<RwLock<Discovery>>,
        db: Arc<DB>,
        kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
        data_radius: Arc<RwLock<U256>>,
        protocol: ProtocolKind,
    ) -> Result<UnboundedSender<OverlayRequest>, String> {
        let (request_tx, request_rx) = mpsc::unbounded_channel();
        let internal_request_tx = request_tx.clone();

        tokio::spawn(async move {
            let mut service = Self {
                discovery,
                db,
                kbuckets,
                data_radius,
                protocol,
                peers_to_ping: HashSetDelay::default(),
                request_rx,
                request_tx: internal_request_tx,
            };

            service.start().await;
        });

        Ok(request_tx)
    }

    async fn start(&mut self) {
        loop {
            tokio::select! {
                Some(request) = self.request_rx.recv() => self.process_request(request).await,
                Some(Ok(node_id)) = self.peers_to_ping.next() => {
                    // If the node is in the routing table, ping it and re-queue the node.
                    let key = kbucket::Key::from(node_id);
                    let node =  {
                        if let kbucket::Entry::Present(entry, _) = self.kbuckets.write().await.entry(&key) {
                        // Re-queue the node.
                        self.peers_to_ping.insert(node_id);
                        Some(entry.value().clone())
                        } else { None }
                    };

                    if let Some(node) = node {
                        self.ping_node(&node.enr()).await;
                    }
                }
                _ = OverlayService::bucket_maintenance_poll(&self.kbuckets) => {}
            }
        }
    }

    /// Maintains the routing table.
    ///
    /// Consumes previously applied pending entries from the `KBucketsTable`. An `AppliedPending`
    /// result is recorded when a pending bucket entry replaces a disconnected entry in the
    /// respective bucket.
    async fn bucket_maintenance_poll(kbuckets: &Arc<RwLock<KBucketsTable<NodeId, Node>>>) {
        // Drain applied pending entries from the routing table.
        if let Some(entry) = kbuckets.write().await.take_applied_pending() {
            debug!(
                "Node {:?} inserted and node {:?} evicted",
                entry.inserted.into_preimage(),
                entry.evicted.map(|n| n.key.into_preimage())
            );
        }
    }

    /// Returns the local ENR of the node.
    async fn local_enr(&self) -> Enr {
        self.discovery.read().await.discv5.local_enr()
    }

    /// Returns the data radius of the node.
    async fn data_radius(&self) -> U256 {
        self.data_radius.read().await.clone()
    }

    /// Processes an overlay request.
    async fn process_request(&mut self, request: OverlayRequest) {
        // For incoming requests, handle the request, possibly, send the response over the channel,
        // and then process the request.
        //
        // For outgoing requests, send the request via a TALK request over Discovery v5, send the
        // response over the channel, and then process the response. There may not be a response
        // channel if the request was initiated internally (e.g. for maintenance).
        match request.direction {
            RequestDirection::Incoming { source } => {
                let response = self
                    .handle_request(request.request.clone(), source.clone())
                    .await;
                if let Some(responder) = request.responder {
                    let _ = responder.send(response);
                }
                match request.request {
                    Request::Ping(ping) => self.process_ping(ping, source).await,
                    _ => {}
                }
            }
            RequestDirection::Outgoing { destination } => {
                let response = self
                    .send_talk_req(request.request, destination.clone())
                    .await;
                if let Some(responder) = request.responder {
                    let _ = responder.send(response.clone());
                }
                match response {
                    Ok(response) => {
                        self.process_response(response, destination).await;
                    }
                    Err(error) => {
                        debug!("Request failed with error {}", error);
                        self.process_request_failure(destination).await
                    }
                }
            }
        }
    }

    /// Attempts to build a response for a request.
    async fn handle_request(
        &mut self,
        request: Request,
        source: NodeId,
    ) -> Result<Response, String> {
        match request {
            Request::Ping(ping) => Ok(Response::Pong(self.handle_ping(ping, source).await?)),
            Request::FindNodes(find_nodes) => {
                Ok(Response::Nodes(self.handle_find_nodes(find_nodes).await?))
            }
            Request::FindContent(find_content) => Ok(Response::FoundContent(
                self.handle_find_content(find_content).await?,
            )),
        }
    }

    /// Attempts to build a Pong response for a Ping request.
    async fn handle_ping(&self, request: Ping, source: NodeId) -> Result<Pong, String> {
        debug!(
            "Got overlay ping request {:?} from node. Node: {}",
            request, source
        );
        let enr_seq = self.local_enr().await.seq();
        let data_radius = self.data_radius().await;
        Ok(Pong {
            enr_seq,
            data_radius,
        })
    }

    /// Attempts to build a Nodes repsonse for a FindNodes request.
    async fn handle_find_nodes(&self, request: FindNodes) -> Result<Nodes, String> {
        let distances64: Vec<u64> = request.distances.iter().map(|x| (*x).into()).collect();
        let enrs = self.nodes_by_distance(distances64).await;
        // from spec: total = The total number of Nodes response messages being sent.
        // TODO: support returning multiple messages
        Ok(Nodes { total: 1, enrs })
    }

    /// Attempts to build a FoundContent response for a FindContent request.
    async fn handle_find_content(&self, request: FindContent) -> Result<FoundContent, String> {
        match self.db.get(&request.content_key) {
            Ok(Some(value)) => Ok(FoundContent {
                enrs: vec![],
                payload: value,
            }),
            Ok(None) => {
                let enrs = self.find_nodes_close_to_content(request.content_key).await;
                Ok(FoundContent {
                    enrs,
                    payload: vec![],
                })
            }
            Err(e) => panic!("Unable to respond to FindContent: {}", e),
        }
    }

    /// Processes a ping request from some source node.
    async fn process_ping(&mut self, ping: Ping, source: NodeId) {
        // If the node is in the routing table, then check if we need to update the node.
        if let Some(mut node) = self.get_node(&source, true).await {
            // TODO: Request ENR via Discovery v5. If the ENR sequence number has changed, then the
            // node's address info may have changed. The TalkRequest object does not contain the
            // requester's ENR, only its NodeId.
            if node.data_radius() != ping.data_radius {
                node.set_data_radius(ping.data_radius);
            }
        } else {
            // We cannot add the node to the routing table here because we do not know the node's ENR.
            // Without the ENR, we have no way to contact the node. Thus, we cannot add the node to the
            // ping queue either. Once the TODO above is completed, then we can retrieve the ENR for the
            // node.
        }
    }

    /// Sends a TALK request via Discovery v5 to some destination node.
    async fn send_talk_req(&self, request: Request, destination: Enr) -> Result<Response, String> {
        match self
            .discovery
            .read()
            .await
            .send_talkreq(
                destination,
                self.protocol.to_string(),
                Message::Request(request).to_bytes(),
            )
            .await
        {
            Ok(talk_resp) => match Message::from_bytes(&talk_resp) {
                Ok(Message::Response(response)) => Ok(response),
                Ok(_) => Err("Unexpected response to TALK request".to_owned()),
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        }
    }

    /// Processes a failed request intended for some destination node.
    async fn process_request_failure(&mut self, destination: Enr) {
        // Attempt to mark the node with a disconnected status.
        let node_id = destination.node_id();
        let _ = self
            .update_node_connection_state(node_id, ConnectionState::Disconnected)
            .await;

        // Remove the node from the ping queue.
        self.peers_to_ping.remove(&node_id);
    }

    /// Processes a response to an outgoing request from some source node.
    async fn process_response(&mut self, response: Response, source: Enr) {
        // Attempt to mark the node is connected. If the node is present in the routing table, then
        // use the existing entry's value and direction. Otherwise, build a new entry from the source
        // ENR and establish a connection in the outgoing direction, because this node is responding
        // to our request.
        let key = kbucket::Key::from(source.node_id());
        let (node, direction) = match self.kbuckets.write().await.entry(&key) {
            kbucket::Entry::Present(entry, status) => (entry.value().clone(), status.direction),
            kbucket::Entry::Pending(ref mut entry, status) => {
                (entry.value().clone(), status.direction)
            }
            _ => {
                // TODO: Should we use a different default radius?
                let node = Node {
                    enr: source.clone(),
                    data_radius: U256::from(u64::MAX),
                };
                (node, ConnectionDirection::Outgoing)
            }
        };
        self.connect_node(node, direction).await;

        match response {
            Response::Pong(pong) => self.process_pong(pong, source).await,
            Response::Nodes(nodes) => self.process_nodes(nodes, source).await,
            Response::FoundContent(found_content) => {
                self.process_found_content(found_content, source).await
            }
        }
    }

    /// Processes a Pong response.
    ///
    /// Refreshes the node if necessary. Attempts to mark the node as connected.
    async fn process_pong(&mut self, pong: Pong, source: Enr) {
        let node_id = source.node_id();
        debug!("Processing Pong response from node {}", node_id);

        // If the ENR sequence number in pong is less than the ENR sequence number for the routing
        // table entry, then request the node.
        //
        // If the node's data radius is different from the present entry, then update the node.
        if let Some(mut node) = self.get_node(&node_id, true).await {
            if node.enr().seq() < pong.enr_seq {
                self.request_node(&source).await;
            }
            if node.data_radius() != pong.data_radius {
                node.set_data_radius(pong.data_radius);
            }
        }

        // We assume that the source node is already in the routing table, because we sent a ping.
        // Ensure that the node has a connected status. Do not change the connection direction.
        match self
            .update_node_connection_state(node_id, ConnectionState::Connected)
            .await
        {
            Ok(_) => {}
            Err(FailureReason::KeyNonExistant) => {}
            Err(other) => {
                debug!("Update for pong failed with error {:?}", other);

                // If the update fails, then remove the node from the ping queue.
                self.peers_to_ping.remove(&node_id);
            }
        }
    }

    /// Processes a Nodes response.
    async fn process_nodes(&mut self, nodes: Nodes, source: Enr) {
        // Process the nodes in the response.
        // TODO: Add data radius to Nodes response?
        debug!("Processing Nodes response from node {}", source.node_id());
        let discovered = nodes
            .enrs
            .into_iter()
            .map(|enr| Node {
                enr,
                data_radius: U256::from(u64::MAX),
            })
            .collect();
        self.process_discovered_nodes(discovered).await;
    }

    /// Processes a FoundContent response.
    async fn process_found_content(&mut self, found_content: FoundContent, source: Enr) {
        // If the response contains a list of nodes, then process those nodes.
        // TODO: Add data radius to FoundContent response?
        debug!(
            "Processing FoundContent response from node {}",
            source.node_id()
        );
        let discovered = found_content
            .enrs
            .iter()
            .map(|enr| Node {
                enr: enr.enr(),
                data_radius: U256::from(u64::MAX),
            })
            .collect();
        self.process_discovered_nodes(discovered).await;
    }

    /// Processes nodes discovered from a FindNode or FindContent request.
    async fn process_discovered_nodes(&mut self, nodes: Vec<Node>) {
        let local_node_id = self.local_enr().await.node_id();

        for node in nodes {
            let node_id = node.enr.node_id();

            // Ignore ourself.
            if node_id == local_node_id {
                continue;
            }

            let key = kbucket::Key::from(node_id);

            // Acquire write lock here so that we can perform node lookup and insert/update atomically.
            // This ensures that we hold the lock until the end of the code block.
            let mut kbuckets = self.kbuckets.write().await;

            // If the node is in the routing table, then check to see if we should update its entry.
            // If the node is not in the routing table, then add the node in a disconnected state.
            // A subsequent ping will establish connectivity with the node. If the insertion succeeds,
            // then add the node to the ping queue. Ignore insertion failures.
            let optional_node = match kbuckets.entry(&key) {
                kbucket::Entry::Present(entry, _) => Some(entry.value().clone()),
                kbucket::Entry::Pending(ref mut entry, _) => Some(entry.value().clone()),
                _ => None,
            };
            if let Some(present_node) = optional_node {
                if present_node.enr().seq() < node.enr().seq() {
                    let update = Node {
                        enr: node.enr(),
                        data_radius: present_node.data_radius(),
                    };

                    // The update removed the node because it would violate the incoming peers condition
                    // or a bucket/table filter.
                    if let UpdateResult::Failed(reason) = kbuckets.update_node(&key, update, None) {
                        self.peers_to_ping.remove(&node_id);
                        debug!(
                            "Failed to update discovered node. Node: {}, Reason: {:?}",
                            node_id, reason
                        );
                    }
                }
            } else {
                let status = NodeStatus {
                    state: ConnectionState::Disconnected,
                    direction: ConnectionDirection::Outgoing,
                };
                match kbuckets.insert_or_update(&key, node, status) {
                    InsertResult::Inserted => {
                        debug!("Discovered node added to routing table. Node: {}", node_id);
                        self.peers_to_ping.insert(node_id);
                    }
                    InsertResult::Pending { disconnected } => {
                        // The disconnected node is the least-recently connected entry that is
                        // currently considered disconnected. This node should be pinged to check
                        // for connectivity.
                        //
                        // The discovered node was inserted as a pending entry that will be inserted
                        // after some timeout if the disconnected node is not updated.
                        if let kbucket::Entry::Present(node_to_ping, _) =
                            kbuckets.entry(&disconnected)
                        {
                            self.ping_node(&node_to_ping.value().enr()).await;
                        }
                    }
                    _ => {
                        debug!(
                            "Discovered node not added to routing table. Node: {}",
                            node_id
                        );
                    }
                }
            }
        }
    }

    /// Returns a vector of all the ENRs of nodes currently contained in the routing table.
    async fn table_entries_enr(&self) -> Vec<Enr> {
        self.kbuckets
            .write()
            .await
            .iter()
            .map(|entry| entry.node.value.enr().clone())
            .collect()
    }

    /// Returns a vector of the ENRs of the closest nodes by the given log2 distances.
    async fn nodes_by_distance(&self, mut log2_distances: Vec<u64>) -> Vec<Enr> {
        let mut nodes_to_send = Vec::new();
        log2_distances.sort_unstable();
        log2_distances.dedup();

        let mut log2_distances = log2_distances.as_slice();
        if let Some(0) = log2_distances.first() {
            // If the distance is 0 send our local ENR.
            nodes_to_send.push(self.local_enr().await);
            log2_distances = &log2_distances[1..];
        }

        if !log2_distances.is_empty() {
            let mut kbuckets = self.kbuckets.write().await;
            for node in kbuckets
                .nodes_by_distances(&log2_distances, FIND_NODES_MAX_NODES)
                .into_iter()
                .map(|entry| entry.node.value.clone())
            {
                nodes_to_send.push(node.enr());
            }
        }
        nodes_to_send
    }

    /// Returns list of nodes closer to content than self, sorted by distance.
    async fn find_nodes_close_to_content(&self, content_key: Vec<u8>) -> Vec<SszEnr> {
        let self_node_id = self.local_enr().await.node_id();
        let self_distance = xor_two_values(&content_key, &self_node_id.raw().to_vec());

        let mut nodes_with_distance: Vec<(Vec<u8>, Enr)> = self
            .table_entries_enr()
            .await
            .into_iter()
            .map(|enr| {
                (
                    xor_two_values(&content_key, &enr.node_id().raw().to_vec()),
                    enr,
                )
            })
            .collect();

        nodes_with_distance.sort_by(|a, b| a.0.cmp(&b.0));

        let closest_nodes = nodes_with_distance
            .into_iter()
            .take(FIND_CONTENT_MAX_NODES)
            .filter(|node_record| &node_record.0 < &self_distance)
            .map(|node_record| SszEnr::new(node_record.1))
            .collect();

        closest_nodes
    }

    /// Attempts to insert a newly connected node or update an existing node to connected.
    async fn connect_node(&mut self, node: Node, connection_direction: ConnectionDirection) {
        let node_id = node.enr().node_id();
        let key = kbucket::Key::from(node_id);
        let status = NodeStatus {
            state: ConnectionState::Connected,
            direction: connection_direction,
        };

        let mut node_to_ping = None;
        match self
            .kbuckets
            .write()
            .await
            .insert_or_update(&key, node, status)
        {
            InsertResult::Inserted => {
                // The node was inserted into the routing table.
                debug!(
                    "New connected node added to routing table. Node: {}",
                    node_id
                );
                self.peers_to_ping.insert(node_id);
            }
            InsertResult::Pending { disconnected } => {
                // The disconnected node is the least-recently connected entry that is
                // currently considered disconnected. This node should be pinged to check
                // for connectivity.
                node_to_ping = Some(disconnected);
            }
            InsertResult::StatusUpdated {
                promoted_to_connected,
            }
            | InsertResult::Updated {
                promoted_to_connected,
            } => {
                // The node existed in the routing table, and it was updated to connected.
                if promoted_to_connected {
                    debug!("Node promoted to connected. Node: {}", node_id);
                    self.peers_to_ping.insert(node_id);
                }
            }
            InsertResult::ValueUpdated | InsertResult::UpdatedPending => {}
            InsertResult::Failed(reason) => {
                self.peers_to_ping.remove(&node_id);
                debug!(
                    "Could not insert node. Node: {}, Reason: {:?}",
                    node_id, reason
                );
            }
        }

        // Ping node to check for connectivity. See comment above for reasoning.
        if let Some(key) = node_to_ping {
            match self.kbuckets.write().await.entry(&key) {
                kbucket::Entry::Present(entry, _) => {
                    self.ping_node(&entry.value().enr()).await;
                }
                kbucket::Entry::Pending(ref mut entry, _) => {
                    self.ping_node(&entry.value().enr()).await;
                }
                _ => {}
            }
        }
    }

    /// Attempts to update the connection state of a node.
    async fn update_node_connection_state(
        &mut self,
        node_id: NodeId,
        state: ConnectionState,
    ) -> Result<(), FailureReason> {
        let key = kbucket::Key::from(node_id);
        match self
            .kbuckets
            .write()
            .await
            .update_node_status(&key, state, None)
        {
            UpdateResult::Failed(reason) => match reason {
                FailureReason::KeyNonExistant => Err(FailureReason::KeyNonExistant),
                other => {
                    warn!(
                        "Could not update node to {:?}. Node: {}, Reason: {:?}",
                        state, node_id, other
                    );

                    Err(other)
                }
            },
            _ => {
                debug!("Node set to {:?}. Node: {}", state, node_id);
                Ok(())
            }
        }
    }

    /// Submits a request to ping a destination (target) node.
    async fn ping_node(&self, destination: &Enr) {
        let enr_seq = self.local_enr().await.seq();
        let data_radius = self.data_radius().await;
        let ping = Request::Ping(Ping {
            enr_seq,
            data_radius,
        });
        let request = OverlayRequest {
            request: ping,
            direction: RequestDirection::Outgoing {
                destination: destination.clone(),
            },
            responder: None,
        };
        let _ = self.request_tx.send(request);
    }

    /// Submits a request for the node info of a destination (target) node.
    async fn request_node(&self, destination: &Enr) {
        let find_nodes = Request::FindNodes(FindNodes { distances: vec![0] });
        let request = OverlayRequest {
            request: find_nodes,
            direction: RequestDirection::Outgoing {
                destination: destination.clone(),
            },
            responder: None,
        };
        let _ = self.request_tx.send(request);
    }

    /// Returns an ENR if one is known for the given NodeId.
    async fn get_node(&self, node_id: &NodeId, include_pending: bool) -> Option<Node> {
        let key = kbucket::Key::from(*node_id);
        match self.kbuckets.write().await.entry(&key) {
            kbucket::Entry::Present(entry, _) => Some(entry.value().clone()),
            kbucket::Entry::Pending(ref mut entry, _) => {
                if include_pending {
                    Some(entry.value().clone())
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}
