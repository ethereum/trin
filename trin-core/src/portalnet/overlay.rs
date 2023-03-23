use std::{
    collections::{BTreeMap, HashSet},
    fmt::{Debug, Display},
    marker::{PhantomData, Sync},
    sync::Arc,
    time::Duration,
};

use discv5::{
    enr::NodeId,
    kbucket::{Filter, KBucketsTable, NodeStatus, MAX_NODES_PER_BUCKET},
    TalkRequest,
};
use futures::channel::oneshot;
use parking_lot::RwLock;
use ssz::Encode;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, error, info, warn};
use utp_rs::socket::UtpSocket;

use crate::portalnet::{
    discovery::{Discovery, UtpEnr},
    overlay_service::{
        OverlayCommand, OverlayRequest, OverlayRequestError, OverlayService, RequestDirection,
        UTP_CONN_CFG,
    },
    storage::ContentStore,
    types::{
        messages::{
            Accept, Content, CustomPayload, FindContent, FindNodes, Message, Nodes, Offer, Ping,
            Pong, PopulatedOffer, ProtocolId, Request, Response,
        },
        node::Node,
    },
};
use ethportal_api::OverlayContentKey;
use trin_types::content_key::RawContentKey;
use trin_types::distance::{Distance, Metric};
use trin_types::enr::Enr;
use trin_utils::bytes::hex_encode;
use trin_validation::validator::Validator;

/// Configuration parameters for the overlay network.
#[derive(Clone)]
pub struct OverlayConfig {
    pub bootnode_enrs: Vec<Enr>,
    pub bucket_pending_timeout: Duration,
    pub max_incoming_per_bucket: usize,
    pub table_filter: Option<Box<dyn Filter<Node>>>,
    pub bucket_filter: Option<Box<dyn Filter<Node>>>,
    pub ping_queue_interval: Option<Duration>,
    pub enable_metrics: bool,
    pub query_parallelism: usize,
    pub query_timeout: Duration,
    pub query_peer_timeout: Duration,
    pub query_num_results: usize,
    pub findnodes_query_distances_per_peer: usize,
}

impl Default for OverlayConfig {
    fn default() -> Self {
        Self {
            bootnode_enrs: vec![],
            bucket_pending_timeout: Duration::from_secs(60),
            max_incoming_per_bucket: 16,
            table_filter: None,
            bucket_filter: None,
            ping_queue_interval: None,
            enable_metrics: false,
            query_parallelism: 3, // (recommended α from kademlia paper)
            query_peer_timeout: Duration::from_secs(10),
            query_timeout: Duration::from_secs(60),
            query_num_results: MAX_NODES_PER_BUCKET,
            findnodes_query_distances_per_peer: 3,
        }
    }
}

/// Overlay protocol is a layer on top of discv5 that handles all requests from the overlay networks
/// (state, history etc.) and dispatch them to the discv5 protocol TalkReq. Each network should
/// implement the overlay protocol and the overlay protocol is where we can encapsulate the logic for
/// handling common network requests/responses.
#[derive(Clone)]
pub struct OverlayProtocol<TContentKey, TMetric, TValidator, TStore> {
    /// Reference to the underlying discv5 protocol
    pub discovery: Arc<Discovery>,
    /// The data store.
    pub store: Arc<RwLock<TStore>>,
    /// The data radius of the local node.
    pub data_radius: Arc<Distance>,
    /// The overlay routing table of the local node.
    kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
    /// The subnetwork protocol of the overlay.
    protocol: ProtocolId,
    /// A sender to send commands to the OverlayService.
    command_tx: UnboundedSender<OverlayCommand<TContentKey>>,
    /// uTP socket.
    utp_socket: Arc<UtpSocket<UtpEnr>>,
    /// Declare the allowed content key types for a given overlay network.
    /// Use a phantom, because we don't store any keys in this struct.
    /// For example, this type is used when decoding a content key received over the network.
    phantom_content_key: PhantomData<TContentKey>,
    /// Associate a metric with the overlay network.
    phantom_metric: PhantomData<TMetric>,
    /// Accepted content validator that makes requests to this/other overlay networks (or trusted
    /// http server)
    validator: Arc<TValidator>,
}

impl<
        TContentKey: 'static + OverlayContentKey + Send + Sync,
        TMetric: Metric + Send + Sync,
        TValidator: 'static + Validator<TContentKey> + Send + Sync,
        TStore: 'static + ContentStore + Send + Sync,
    > OverlayProtocol<TContentKey, TMetric, TValidator, TStore>
where
    <TContentKey as TryFrom<Vec<u8>>>::Error: Debug + Display + Send,
{
    pub async fn new(
        config: OverlayConfig,
        discovery: Arc<Discovery>,
        utp_socket: Arc<UtpSocket<UtpEnr>>,
        store: Arc<RwLock<TStore>>,
        data_radius: Distance,
        protocol: ProtocolId,
        validator: Arc<TValidator>,
    ) -> Self {
        let kbuckets = Arc::new(RwLock::new(KBucketsTable::new(
            discovery.local_enr().node_id().into(),
            config.bucket_pending_timeout,
            config.max_incoming_per_bucket,
            config.table_filter,
            config.bucket_filter,
        )));

        let data_radius = Arc::new(data_radius);
        let command_tx = OverlayService::<TContentKey, TMetric, TValidator, TStore>::spawn(
            Arc::clone(&discovery),
            Arc::clone(&store),
            Arc::clone(&kbuckets),
            config.bootnode_enrs,
            config.ping_queue_interval,
            Arc::clone(&data_radius),
            protocol.clone(),
            Arc::clone(&utp_socket),
            config.enable_metrics,
            Arc::clone(&validator),
            config.query_timeout,
            config.query_peer_timeout,
            config.query_parallelism,
            config.query_num_results,
            config.findnodes_query_distances_per_peer,
        )
        .await;

        Self {
            discovery,
            data_radius,
            kbuckets,
            store,
            protocol,
            command_tx,
            utp_socket,
            phantom_content_key: PhantomData,
            phantom_metric: PhantomData,
            validator,
        }
    }

    /// Returns the subnetwork protocol of the overlay protocol.
    pub fn protocol(&self) -> &ProtocolId {
        &self.protocol
    }

    /// Returns the ENR of the local node.
    pub fn local_enr(&self) -> Enr {
        self.discovery.local_enr()
    }

    /// Returns the data radius of the local node.
    pub fn data_radius(&self) -> Distance {
        *self.data_radius
    }

    /// Processes a single Discovery v5 TALKREQ message.
    pub async fn process_one_request(
        &self,
        talk_request: &TalkRequest,
    ) -> Result<Response, OverlayRequestError> {
        let request = match Message::try_from(Vec::<u8>::from(talk_request.body())) {
            Ok(message) => match Request::try_from(message) {
                Ok(request) => request,
                Err(err) => return Err(OverlayRequestError::InvalidRequest(err.to_string())),
            },
            Err(_) => return Err(OverlayRequestError::DecodeError),
        };
        let direction = RequestDirection::Incoming {
            id: talk_request.id().clone(),
            source: *talk_request.node_id(),
        };

        // Send the request and wait on the response.
        self.send_overlay_request(request, direction).await
    }

    /// Propagate gossip accepted content via OFFER/ACCEPT, return number of peers propagated
    pub fn propagate_gossip(&self, content: Vec<(TContentKey, Vec<u8>)>) -> usize {
        let kbuckets = Arc::clone(&self.kbuckets);
        crate::portalnet::overlay_service::propagate_gossip_cross_thread(
            content,
            kbuckets,
            self.command_tx.clone(),
        )
    }

    /// Returns a vector of all ENR node IDs of nodes currently contained in the routing table.
    pub fn table_entries_id(&self) -> Vec<NodeId> {
        self.kbuckets
            .write()
            .iter()
            .map(|entry| *entry.node.key.preimage())
            .collect()
    }

    /// Returns a vector of all the ENRs of nodes currently contained in the routing table.
    pub fn table_entries_enr(&self) -> Vec<Enr> {
        self.kbuckets
            .write()
            .iter()
            .map(|entry| entry.node.value.enr().clone())
            .collect()
    }

    /// Returns a map (BTree for its ordering guarantees) with:
    ///     key: usize representing bucket index
    ///     value: Vec of tuples, each tuple represents a node
    pub fn bucket_entries(
        &self,
    ) -> BTreeMap<usize, Vec<(NodeId, Enr, NodeStatus, Distance, Option<String>)>> {
        self.kbuckets
            .read()
            .buckets_iter()
            .enumerate()
            .filter(|(_, bucket)| bucket.num_entries() > 0)
            .map(|(index, bucket)| {
                (
                    index,
                    bucket
                        .iter()
                        .map(|node| {
                            // "c" is used as short-hand for "client" within the ENR's key-values.
                            let client_info: Option<String> = match node.value.enr().clone().get("c") {
                                Some(slice) => {
                                    match std::str::from_utf8(slice) {
                                        Ok(client_string) => Some(client_string.to_string()),
                                        Err(err) => {
                                            error!("Failed to parse remote client info from ENR: {err:?}");
                                            None
                                        }
                                    }
                                }
                                None => None
                            };
                            (
                                *node.key.preimage(),
                                node.value.enr().clone(),
                                node.status,
                                node.value.data_radius(),
                                client_info,
                            )
                        })
                        .collect(),
                )
            })
            .collect()
    }

    /// Sends a `Ping` request to `enr`.
    pub async fn send_ping(&self, enr: Enr) -> Result<Pong, OverlayRequestError> {
        // Construct the request.
        let enr_seq = self.discovery.local_enr().seq();
        let data_radius = self.data_radius();
        let custom_payload = CustomPayload::from(data_radius.as_ssz_bytes());
        let request = Ping {
            enr_seq,
            custom_payload,
        };

        let direction = RequestDirection::Outgoing { destination: enr };

        // Send the request and wait on the response.
        match self
            .send_overlay_request(Request::Ping(request), direction)
            .await
        {
            Ok(Response::Pong(pong)) => Ok(pong),
            Ok(_) => Err(OverlayRequestError::InvalidResponse),
            Err(error) => Err(error),
        }
    }

    /// Sends a `FindNodes` request to `enr`.
    pub async fn send_find_nodes(
        &self,
        enr: Enr,
        distances: Vec<u16>,
    ) -> Result<Nodes, OverlayRequestError> {
        // Construct the request.
        validate_find_nodes_distances(&distances)?;
        let request = FindNodes { distances };
        let direction = RequestDirection::Outgoing { destination: enr };

        // Send the request and wait on the response.
        match self
            .send_overlay_request(Request::FindNodes(request), direction)
            .await
        {
            Ok(Response::Nodes(nodes)) => Ok(nodes),
            Ok(_) => Err(OverlayRequestError::InvalidResponse),
            Err(error) => Err(error),
        }
    }

    /// Sends a `FindContent` request for `content_key` to `enr`.
    pub async fn send_find_content(
        &self,
        enr: Enr,
        content_key: Vec<u8>,
    ) -> Result<Content, OverlayRequestError> {
        // Construct the request.
        let request = FindContent {
            content_key: content_key.clone(),
        };
        let direction = RequestDirection::Outgoing {
            destination: enr.clone(),
        };

        // Send the request and wait on the response.
        match self
            .send_overlay_request(Request::FindContent(request), direction)
            .await
        {
            Ok(Response::Content(found_content)) => {
                match found_content {
                    Content::Content(_) => Ok(found_content),
                    Content::Enrs(_) => Ok(found_content),
                    // Init uTP stream if `connection_id`is received
                    Content::ConnectionId(conn_id) => {
                        let conn_id = u16::from_be(conn_id);
                        let content = self.init_find_content_stream(enr, conn_id).await?;
                        let content_key = TContentKey::try_from(content_key).map_err(|err| {
                            OverlayRequestError::FailedValidation(format!(
                                "Error decoding content key for received utp content: {err}"
                            ))
                        })?;
                        match self
                            .validator
                            .validate_content(&content_key, &content)
                            .await
                        {
                            Ok(_) => Ok(Content::Content(content)),
                            Err(msg) => Err(OverlayRequestError::FailedValidation(format!(
                                "Network: {:?}, Reason: {:?}",
                                self.protocol, msg
                            ))),
                        }
                    }
                }
            }
            Ok(_) => Err(OverlayRequestError::InvalidResponse),
            Err(error) => Err(error),
        }
    }

    /// Initialize FindContent uTP stream with remote node
    async fn init_find_content_stream(
        &self,
        enr: Enr,
        conn_id: u16,
    ) -> Result<Vec<u8>, OverlayRequestError> {
        let cid = utp_rs::cid::ConnectionId {
            recv: conn_id,
            send: conn_id.wrapping_add(1),
            peer: crate::portalnet::discovery::UtpEnr(enr),
        };
        let mut stream = self
            .utp_socket
            .connect_with_cid(cid, UTP_CONN_CFG)
            .await
            .map_err(|err| OverlayRequestError::UtpError(format!("{err:?}")))?;
        let mut data = vec![];
        stream
            .read_to_eof(&mut data)
            .await
            .map_err(|err| OverlayRequestError::UtpError(format!("{:?}", err)))?;

        Ok(data)
    }

    /// Offer is sent in order to store content to k nodes with radii that contain content-id
    /// Offer is also sent to nodes after FindContent (POKE)
    pub async fn send_offer(
        &self,
        content_keys: Vec<RawContentKey>,
        enr: Enr,
    ) -> Result<Accept, OverlayRequestError> {
        // Construct the request.
        let request = Offer {
            content_keys: content_keys.clone(),
        };
        let direction = RequestDirection::Outgoing {
            destination: enr.clone(),
        };

        // Send the request and wait on the response.
        match self
            .send_overlay_request(Request::Offer(request), direction)
            .await
        {
            Ok(Response::Accept(accept)) => Ok(accept),
            Ok(_) => Err(OverlayRequestError::InvalidResponse),
            Err(error) => Err(error),
        }
    }

    /// Send Offer request without storing the content into db
    pub async fn send_populated_offer(
        &self,
        enr: Enr,
        content_key: RawContentKey,
        content_value: Vec<u8>,
    ) -> Result<Accept, OverlayRequestError> {
        // Construct the request.
        let request = Request::PopulatedOffer(PopulatedOffer {
            content_items: vec![(content_key, content_value)],
        });

        let direction = RequestDirection::Outgoing {
            destination: enr.clone(),
        };

        // Send the request and wait on the response.
        match self.send_overlay_request(request, direction).await {
            Ok(Response::Accept(accept)) => Ok(accept),
            Ok(_) => Err(OverlayRequestError::InvalidResponse),
            Err(error) => Err(error),
        }
    }

    /// Performs a content lookup for `target`.
    /// Returns the target content along with the peers traversed during content lookup.
    pub async fn lookup_content(&self, target: TContentKey) -> (Option<Vec<u8>>, Vec<NodeId>) {
        let (tx, rx) = oneshot::channel();
        let content_id = target.content_id();

        if let Err(err) = self.command_tx.send(OverlayCommand::FindContentQuery {
            target,
            callback: tx,
        }) {
            warn!(
                protocol = %self.protocol,
                error = %err,
                content.id = %hex_encode(content_id),
                "Error submitting FindContent query to service"
            );
            return (None, vec![]);
        }

        match rx.await {
            Ok(result) => result,
            Err(err) => {
                warn!(
                    protocol = %self.protocol,
                    error = %err,
                    content.id = %hex_encode(content_id),
                    "Error receiving content from service",
                );
                (None, vec![])
            }
        }
    }

    /// Sends a request through the overlay service.
    async fn send_overlay_request(
        &self,
        request: Request,
        direction: RequestDirection,
    ) -> Result<Response, OverlayRequestError> {
        let (tx, rx) = oneshot::channel();
        let overlay_request = OverlayRequest::new(request, direction, Some(tx), None);
        if let Err(error) = self
            .command_tx
            .send(OverlayCommand::Request(overlay_request))
        {
            warn!(
                protocol = %self.protocol,
                error = %error,
                "Error submitting request to service",
            );
            return Err(OverlayRequestError::ChannelFailure(error.to_string()));
        }

        // Wait on the response.
        match rx.await {
            Ok(result) => result,
            Err(error) => Err(OverlayRequestError::ChannelFailure(error.to_string())),
        }
    }

    pub async fn ping_bootnodes(&self) {
        // Trigger bonding with bootnodes, at both the base layer and portal overlay.
        // The overlay ping via talkreq will trigger a session at the base layer, then
        // a session on the (overlay) portal network.
        let mut successfully_bonded_bootnode = false;
        let enrs = self.discovery.table_entries_enr();
        if enrs.is_empty() {
            error!(
                protocol = %self.protocol,
                "No bootnodes provided to join portal network",
            );
            return;
        }
        for enr in enrs {
            debug!(bootnode.enr = %enr, "Attempting to bond with bootnode");
            let ping_result = self.send_ping(enr.clone()).await;

            match ping_result {
                Ok(_) => {
                    info!(bootnode.enr = %enr, "Bonded with bootnode");
                    successfully_bonded_bootnode = true;
                }
                Err(err) => {
                    error!(
                        protocol = %self.protocol,
                        error = %err,
                        bootnode.enr = %enr,
                        "Error bonding with bootnode",
                    );
                }
            }
        }
        if !successfully_bonded_bootnode {
            error!(
                protocol = %self.protocol,
                "Failed to bond with any bootnodes",
            );
        }
    }
}

fn validate_find_nodes_distances(distances: &Vec<u16>) -> Result<(), OverlayRequestError> {
    if distances.len() == 0 {
        return Err(OverlayRequestError::InvalidRequest(
            "Invalid distances: Empty list".to_string(),
        ));
    }
    if distances.len() > 256 {
        return Err(OverlayRequestError::InvalidRequest(
            "Invalid distances: More than 256 elements".to_string(),
        ));
    }
    let invalid_distances: Vec<&u16> = distances.iter().filter(|val| val > &&256u16).collect();
    if invalid_distances.len() > 0 {
        return Err(OverlayRequestError::InvalidRequest(format!(
            "Invalid distances: Distances greater than 256 are not allowed. Found: {:?}",
            invalid_distances
        )));
    }
    let unique: HashSet<u16> = HashSet::from_iter(distances.iter().cloned());
    if unique.len() != distances.len() {
        return Err(OverlayRequestError::InvalidRequest(
            "Invalid distances: Duplicate elements detected".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(vec![0u16])]
    #[case(vec![256u16])]
    #[case((0u16..256u16).collect())]
    fn test_nodes_validator_accepts_valid_input(#[case] input: Vec<u16>) {
        let result = validate_find_nodes_distances(&input);
        match result {
            Ok(val) => assert_eq!(val, ()),
            Err(_) => panic!("Valid test case fails"),
        }
    }

    #[rstest]
    #[case(vec![], "Empty list")]
    #[case((0u16..257u16).collect(), "More than 256")]
    #[case(vec![257u16], "Distances greater than")]
    #[case(vec![0u16, 0u16, 1u16], "Duplicate elements detected")]
    fn test_nodes_validator_rejects_invalid_input(#[case] input: Vec<u16>, #[case] msg: String) {
        let result = validate_find_nodes_distances(&input);
        match result {
            Ok(_) => panic!("Invalid test case passed"),
            Err(err) => assert!(err.to_string().contains(&msg)),
        }
    }
}
