use std::collections::HashSet;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use super::{
    discovery::Discovery,
    overlay_service::{Node, OverlayRequest, OverlayService, RequestDirection},
    types::{content_key::OverlayContentKey, uint::U256},
    Enr,
};
use crate::portalnet::storage::PortalStorage;
use crate::portalnet::types::messages::{
    Accept, Content, CustomPayload, FindContent, FindNodes, Message, Nodes, Offer, Ping, Pong,
    ProtocolId, Request, Response,
};

use crate::utp::stream::{ConnectionKey, UtpListener};
use crate::utp::trin_helpers::{UtpAccept, UtpMessage, UtpMessageId};
use discv5::{
    enr::NodeId,
    kbucket::{Filter, KBucketsTable},
    TalkRequest,
};
use futures::channel::oneshot;
use parking_lot::RwLock;
use ssz::Encode;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::RwLock as RwLockT;
use tracing::{debug, warn};

pub use super::overlay_service::OverlayRequestError;

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
pub struct OverlayProtocol<TContentKey> {
    /// Reference to the underlying discv5 protocol
    pub discovery: Arc<Discovery>,
    // Reference to the database instance
    pub storage: Arc<PortalStorage>,
    /// The data radius of the local node.
    pub data_radius: Arc<U256>,
    /// The overlay routing table of the local node.
    kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
    /// The subnetwork protocol of the overlay.
    protocol: ProtocolId,
    /// A sender to send requests to the OverlayService.
    request_tx: UnboundedSender<OverlayRequest>,
    utp_listener: Arc<RwLockT<UtpListener>>,
    /// Declare the allowed content key types for a given overlay network.
    /// Use a phantom, because we don't store any keys in this struct.
    /// For example, this type is used when decoding a content key received over the network.
    phantom_content_key: PhantomData<TContentKey>,
}

impl<TContentKey: OverlayContentKey + Send> OverlayProtocol<TContentKey> {
    pub async fn new(
        config: OverlayConfig,
        discovery: Arc<Discovery>,
        utp_listener: Arc<RwLockT<UtpListener>>,
        storage: Arc<PortalStorage>,
        data_radius: U256,
        protocol: ProtocolId,
    ) -> Self {
        let kbuckets = Arc::new(RwLock::new(KBucketsTable::new(
            discovery.local_enr().node_id().into(),
            config.bucket_pending_timeout,
            config.max_incoming_per_bucket,
            config.table_filter,
            config.bucket_filter,
        )));

        let data_radius = Arc::new(data_radius);
        let request_tx = OverlayService::<TContentKey>::spawn(
            Arc::clone(&discovery),
            Arc::clone(&storage),
            Arc::clone(&kbuckets),
            config.bootnode_enrs,
            config.ping_queue_interval,
            Arc::clone(&data_radius),
            protocol.clone(),
            utp_listener.clone(),
            config.enable_metrics,
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
            utp_listener,
            phantom_content_key: PhantomData,
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
        let direction = RequestDirection::Outgoing { destination: enr };

        // Send the request and wait on the response.
        match self
            .send_overlay_request(Request::FindContent(request), direction)
            .await
        {
            Ok(Response::Content(found_content)) => Ok(found_content),
            Ok(_) => Err(OverlayRequestError::InvalidResponse),
            Err(error) => Err(error),
        }
    }

    /// Offer is sent in order to store content to k nodes with radii that contain content-id
    /// Offer is also sent to nodes after FindContent (POKE)
    pub async fn send_offer(
        &self,
        content_keys: Vec<Vec<u8>>,
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
            Err(_msg) => return Err(OverlayRequestError::DecodeError),
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
                    Err(msg) => Err(OverlayRequestError::OfferError(msg.to_string())),
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
        let connection_id = response.connection_id.clone();

        self.utp_listener
            .write()
            .await
            .listening
            .insert(connection_id.clone(), UtpMessageId::OfferAcceptStream);

        // initiate the connection to the acceptor
        let mut conn = self
            .utp_listener
            .write()
            .await
            .connect(connection_id.clone(), enr.node_id())
            .await?;

        // TODO: Replace this with recv_from
        // Handle STATE packet for SYN
        let mut buf = [0; 1500];
        conn.recv(&mut buf).await?;

        // Return to acceptor: the content key and corresponding data
        let mut content_items: Vec<(Vec<u8>, Vec<u8>)> = vec![];

        for (i, key) in response
            .content_keys
            .clone()
            .iter()
            .zip(content_keys_offered.iter())
        {
            if i == true {
                match self.storage.get(&key.clone()) {
                    Ok(content) => match content {
                        Some(content) => content_items.push((key.clone().into(), content)),
                        None => {}
                    },
                    // should return some error if content not found
                    Err(_) => {}
                }
            }
        }

        let content_message = UtpAccept {
            message: content_items,
        };

        let utp_listener = self.utp_listener.clone();
        tokio::spawn(async move {
            if let Some(conn) = utp_listener
                .write()
                .await
                .utp_connections
                .get_mut(&ConnectionKey {
                    node_id: enr.node_id(),
                    conn_id_recv: connection_id,
                })
            {
                // send the content to the acceptor over a uTP stream
                if let Err(msg) = conn
                    .send_to(&UtpMessage::new(content_message.as_ssz_bytes()).encode()[..])
                    .await
                {
                    debug!("Error sending content {msg}");
                } else {
                    // Close uTP connection
                    if let Err(msg) = conn.close().await {
                        debug!("Unable to close uTP connection!: {msg}")
                    }
                };
            }
        });
        Ok(response)
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
