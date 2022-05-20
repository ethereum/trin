use anyhow::anyhow;
use std::{
    collections::HashSet,
    marker::{PhantomData, Sync},
    sync::Arc,
    time::Duration,
};

use super::{
    discovery::Discovery,
    overlay_service::{Node, OverlayRequest, OverlayService},
    types::{content_key::OverlayContentKey, metric::Metric},
    Enr,
};
use crate::portalnet::{
    storage::PortalStorage,
    types::messages::{
        Accept, Content, CustomPayload, FindContent, FindNodes, Message, Nodes, Offer, Ping, Pong,
        ProtocolId, Request, Response,
    },
};

use crate::{
    portalnet::types::content_key::RawContentKey,
    types::validation::Validator,
    utp::{
        stream::{UtpListenerEvent, UtpListenerRequest, UtpStream, BUF_SIZE},
        trin_helpers::{UtpAccept, UtpMessage, UtpStreamId},
    },
};
use discv5::{
    enr::NodeId,
    kbucket::{Filter, KBucketsTable},
    TalkRequest,
};
use ethereum_types::U256;
use futures::channel::oneshot;
use parking_lot::RwLock;
use ssz::Encode;
use ssz_types::VariableList;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, warn};

pub use super::overlay_service::{OverlayRequestError, RequestDirection};

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
        }
    }
}

/// Overlay protocol is a layer on top of discv5 that handles all requests from the overlay networks
/// (state, history etc.) and dispatch them to the discv5 protocol TalkReq. Each network should
/// implement the overlay protocol and the overlay protocol is where we can encapsulate the logic for
/// handling common network requests/responses.
#[derive(Clone)]
pub struct OverlayProtocol<TContentKey, TMetric, TValidator> {
    /// Reference to the underlying discv5 protocol
    pub discovery: Arc<Discovery>,
    /// Reference to the database instance
    pub storage: Arc<RwLock<PortalStorage>>,
    /// The data radius of the local node.
    pub data_radius: Arc<U256>,
    /// The overlay routing table of the local node.
    kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
    /// The subnetwork protocol of the overlay.
    protocol: ProtocolId,
    /// A sender to send requests to the OverlayService.
    request_tx: UnboundedSender<OverlayRequest>,
    /// A sender to send request to UtpListener
    utp_listener_tx: UnboundedSender<UtpListenerRequest>,
    /// Declare the allowed content key types for a given overlay network.
    /// Use a phantom, because we don't store any keys in this struct.
    /// For example, this type is used when decoding a content key received over the network.
    phantom_content_key: PhantomData<TContentKey>,
    /// Associate a metric with the overlay network.
    phantom_metric: PhantomData<TMetric>,
    /// Declare the Validator type for a given overlay network.
    phantom_validator: PhantomData<TValidator>,
}

impl<
        TContentKey: OverlayContentKey + Send + Sync,
        TMetric: Metric + Send,
        TValidator: 'static + Validator<TContentKey> + Send,
    > OverlayProtocol<TContentKey, TMetric, TValidator>
{
    pub async fn new(
        config: OverlayConfig,
        discovery: Arc<Discovery>,
        utp_listener_tx: UnboundedSender<UtpListenerRequest>,
        storage: Arc<RwLock<PortalStorage>>,
        data_radius: U256,
        protocol: ProtocolId,
        validator: TValidator,
    ) -> Self {
        let kbuckets = Arc::new(RwLock::new(KBucketsTable::new(
            discovery.local_enr().node_id().into(),
            config.bucket_pending_timeout,
            config.max_incoming_per_bucket,
            config.table_filter,
            config.bucket_filter,
        )));

        let data_radius = Arc::new(data_radius);
        let request_tx = OverlayService::<TContentKey, TMetric, TValidator>::spawn(
            Arc::clone(&discovery),
            Arc::clone(&storage),
            Arc::clone(&kbuckets),
            config.bootnode_enrs,
            config.ping_queue_interval,
            Arc::clone(&data_radius),
            protocol.clone(),
            utp_listener_tx.clone(),
            config.enable_metrics,
            validator,
        )
        .await
        .unwrap();

        Self {
            discovery,
            data_radius,
            kbuckets,
            storage,
            protocol,
            request_tx,
            utp_listener_tx,
            phantom_content_key: PhantomData,
            phantom_metric: PhantomData,
            phantom_validator: PhantomData,
        }
    }

    /// Returns the subnetwork protocol of the overlay protocol.
    pub fn protocol(&self) -> &ProtocolId {
        &self.protocol
    }

    /// Returns the ENR of the local node.
    pub fn local_enr(&self) -> Enr {
        self.discovery.discv5.local_enr()
    }

    /// Returns the data radius of the local node.
    pub fn data_radius(&self) -> U256 {
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

    /// Process overlay uTP listener event
    pub fn process_utp_event(&self, event: UtpListenerEvent) {
        // TODO: Handle overlay uTP events
        debug!(
            "Got overlay uTP event: {event:?}, protocol id: {:?}",
            self.protocol
        );
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

        let node_id = enr.node_id();
        let direction = RequestDirection::Outgoing { destination: enr };

        // Send the request and wait on the response.
        debug!("Sending {} dest={}", request, node_id);
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
        let request = FindContent { content_key };
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

                        self.init_find_content_stream(enr, conn_id).await
                    }
                }
            }
            Ok(_) => Err(OverlayRequestError::InvalidResponse),
            Err(error) => Err(error),
        }
    }

    /// Initialize FIndContent uTP stream with remote node
    async fn init_find_content_stream(
        &self,
        enr: Enr,
        conn_id: u16,
    ) -> Result<Content, OverlayRequestError> {
        // initiate the connection to the acceptor
        let (tx, rx) = tokio::sync::oneshot::channel::<UtpStream>();
        let utp_request = UtpListenerRequest::Connect(
            conn_id,
            enr,
            self.protocol.clone(),
            UtpStreamId::FindContentStream,
            tx,
        );

        self.utp_listener_tx.send(utp_request).map_err(|err| {
            OverlayRequestError::UtpError(format!(
                "Unable to send Connect request with FindContent stream to UtpListener: {err}"
            ))
        })?;

        match rx.await {
            Ok(mut conn) => {
                let mut result = Vec::new();
                // Loop and receive all DATA packets, similar to `read_to_end`
                loop {
                    let mut buf = [0; BUF_SIZE];
                    match conn.recv_from(&mut buf).await {
                        Ok((0, _)) => {
                            break;
                        }
                        Ok((bytes, _)) => {
                            result.extend_from_slice(&mut buf[..bytes]);
                        }
                        Err(err) => {
                            warn!("Unable to receive content via uTP: {err}");
                            return Err(OverlayRequestError::UtpError(err.to_string()));
                        }
                    }
                }
                Ok(Content::Content(VariableList::from(result)))
            }
            Err(err) => {
                warn!("Unable to receive from uTP listener channel: {err}");
                Err(OverlayRequestError::UtpError(err.to_string()))
            }
        }
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

        // todo: remove after updating `Offer` to use `ContentKey` type
        let content_keys_offered: Result<Vec<TContentKey>, TContentKey::Error> = content_keys
            .into_iter()
            .map(|key| (TContentKey::try_from)(key))
            .collect();
        let content_keys_offered: Vec<TContentKey> = match content_keys_offered {
            Ok(val) => val,
            Err(_) => return Err(OverlayRequestError::DecodeError),
        };

        // Send the request and wait on the response.
        match self
            .send_overlay_request(Request::Offer(request), direction)
            .await
        {
            Ok(Response::Accept(accept)) => {
                match self
                    .process_accept_response(accept, enr, content_keys_offered)
                    .await
                {
                    Ok(accept) => Ok(accept),
                    Err(err) => Err(OverlayRequestError::OfferError(err.to_string())),
                }
            }
            Ok(_) => Err(OverlayRequestError::InvalidResponse),
            Err(error) => Err(error),
        }
    }

    pub async fn process_accept_response(
        &self,
        response: Accept,
        enr: Enr,
        content_keys_offered: Vec<TContentKey>,
    ) -> anyhow::Result<Accept> {
        let conn_id = response.connection_id.to_be();

        // Do not initialize uTP stream if remote node doesn't have interest in the offered content keys
        if response.content_keys.is_zero() {
            return Ok(response);
        }

        // initiate the connection to the acceptor
        let (tx, rx) = tokio::sync::oneshot::channel::<UtpStream>();
        let utp_request = UtpListenerRequest::Connect(
            conn_id,
            enr,
            self.protocol.clone(),
            UtpStreamId::OfferStream,
            tx,
        );

        self.utp_listener_tx
            .send(utp_request).map_err(|err| anyhow!("Unable to send Connect request to UtpListener when processing ACCEPT message: {err}"))?;

        let mut conn = rx.await?;
        // Handle STATE packet for SYN
        let mut buf = [0; BUF_SIZE];
        conn.recv(&mut buf).await?;

        let content_items = self.provide_requested_content(&response, content_keys_offered);

        let content_message = UtpAccept {
            message: content_items,
        };

        tokio::spawn(async move {
            // send the content to the acceptor over a uTP stream
            if let Err(err) = conn
                .send_to(&UtpMessage::new(content_message.as_ssz_bytes()).encode()[..])
                .await
            {
                warn!("Error sending content {err}");
            };
            // Close uTP connection
            if let Err(err) = conn.close().await {
                warn!("Unable to close uTP connection!: {err}")
            };
        });
        Ok(response)
    }

    /// Provide the requested content key and content value for the acceptor
    fn provide_requested_content(
        &self,
        response: &Accept,
        content_keys_offered: Vec<TContentKey>,
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut content_items: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

        for (i, key) in response
            .content_keys
            .clone()
            .iter()
            .zip(content_keys_offered.iter())
        {
            if i == true {
                match self.storage.read().get(&key.clone()) {
                    Ok(content) => match content {
                        Some(content) => content_items.push((key.clone().into(), content)),
                        None => {}
                    },
                    Err(err) => warn!("Unable to get requested content from portal storage: {err}"),
                }
            }
        }
        content_items
    }

    /// Public method for initiating a network request through the overlay service.
    pub async fn initiate_overlay_request(
        &self,
        request: Request,
    ) -> Result<Response, OverlayRequestError> {
        let direction = RequestDirection::Initialize;
        self.send_overlay_request(request, direction).await
    }

    /// Sends a request through the overlay service.
    async fn send_overlay_request(
        &self,
        request: Request,
        direction: RequestDirection,
    ) -> Result<Response, OverlayRequestError> {
        let (tx, rx) = oneshot::channel();
        let overlay_request = OverlayRequest::new(request, direction, Some(tx));
        if let Err(error) = self.request_tx.send(overlay_request) {
            warn!(
                "Failure sending request over {:?} service channel",
                self.protocol
            );
            return Err(OverlayRequestError::ChannelFailure(error.to_string()));
        }

        // Wait on the response.
        match rx.await {
            Ok(result) => result,
            Err(error) => Err(OverlayRequestError::ChannelFailure(error.to_string())),
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
