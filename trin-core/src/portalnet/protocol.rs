#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use discv5::{Discv5ConfigBuilder, Discv5Event, TalkRequest};
use log::{debug, error, warn};
use rocksdb::{Options, DB};
use serde_json::Value;
use tokio::sync::mpsc;

use crate::utils::get_data_dir;

use super::{
    discovery::{Config as DiscoveryConfig, Discovery},
    overlay::{Config as OverlayConfig, Overlay},
    types::{
        FindContent, FindNodes, FoundContent, HexData, Nodes, Ping, Pong, Request, Response, SszEnr,
    },
    U256,
};
use super::{types::Message, Enr};
use crate::socket;

type Responder<T, E> = mpsc::UnboundedSender<Result<T, E>>;

#[derive(Debug)]
pub enum PortalEndpointKind {
    NodeInfo,
    RoutingTableInfo,
}

#[derive(Debug)]
pub struct PortalEndpoint {
    pub kind: PortalEndpointKind,
    pub resp: Responder<Value, String>,
}

#[derive(Clone)]
pub struct PortalnetConfig {
    pub external_addr: Option<SocketAddr>,
    pub private_key: Option<HexData>,
    pub listen_port: u16,
    pub bootnode_enrs: Vec<Enr>,
    pub data_radius: U256,
}

impl Default for PortalnetConfig {
    fn default() -> Self {
        Self {
            external_addr: None,
            private_key: None,
            listen_port: 4242,
            bootnode_enrs: Vec::<Enr>::new(),
            data_radius: U256::from(u64::MAX), //TODO better data_radius default?
        }
    }
}

pub const PROTOCOL: &str = "portal";

#[derive(Clone)]
pub struct PortalnetProtocol {
    pub discovery: Arc<Discovery>,
    pub overlay: Overlay,
}

pub struct PortalnetEvents {
    discovery: Arc<Discovery>,
    overlay: Overlay,
    protocol_receiver: mpsc::Receiver<Discv5Event>,
    db: DB,
}

pub struct JsonRpcHandler {
    discovery: Arc<Discovery>,
    jsonrpc_rx: mpsc::UnboundedReceiver<PortalEndpoint>,
}

impl JsonRpcHandler {
    pub async fn process_jsonrpc_requests(mut self) {
        while let Some(cmd) = self.jsonrpc_rx.recv().await {
            use PortalEndpointKind::*;

            match cmd.kind {
                NodeInfo => {
                    let node_id = self.discovery.local_enr().to_base64();
                    let _ = cmd.resp.send(Ok(Value::String(node_id)));
                }
                RoutingTableInfo => {
                    let routing_table_info = self
                        .discovery
                        .discv5
                        .table_entries_id()
                        .iter()
                        .map(|node_id| Value::String(node_id.to_string()))
                        .collect();
                    let _ = cmd.resp.send(Ok(Value::Array(routing_table_info)));
                }
            }
        }
    }
}

impl PortalnetEvents {
    /// Receives a request from the talkreq handler and sends a response back
    pub async fn process_discv5_requests(mut self) {
        while let Some(event) = self.protocol_receiver.recv().await {
            debug!("Got discv5 event {:?}", event);

            let request = match event {
                Discv5Event::TalkRequest(r) => r,
                _ => continue,
            };

            let reply = match self.process_one_request(&request).await {
                Ok(r) => Message::Response(r).to_bytes(),
                Err(e) => {
                    error!("failed to process portal event: {}", e);
                    e.into_bytes()
                }
            };

            if let Err(e) = request.respond(reply) {
                warn!("failed to send reply: {}", e);
            }
        }
    }

    async fn process_one_request(&self, talk_request: &TalkRequest) -> Result<Response, String> {
        let protocol = std::str::from_utf8(talk_request.protocol())
            .map_err(|_| "Invalid protocol".to_owned())?;

        if protocol != PROTOCOL {
            return Err("Invalid protocol".to_owned());
        }

        let request = match Message::from_bytes(talk_request.body()) {
            Ok(Message::Request(r)) => r,
            Ok(_) => return Err("Invalid message".to_owned()),
            Err(e) => return Err(format!("Invalid request: {}", e)),
        };

        let response = match request {
            Request::Ping(Ping { .. }) => {
                debug!("Got overlay ping request {:?}", request);
                let enr_seq = self.discovery.local_enr().seq();
                Response::Pong(Pong {
                    enr_seq: enr_seq,
                    data_radius: self.overlay.data_radius(),
                })
            }
            Request::FindNodes(FindNodes { distances }) => {
                let distances64: Vec<u64> = distances.iter().map(|x| (*x).into()).collect();
                let enrs = self.overlay.nodes_by_distance(distances64);
                Response::Nodes(Nodes {
                    // from spec: total = The total number of Nodes response messages being sent.
                    // TODO: support returning multiple messages
                    total: 1 as u8,
                    enrs,
                })
            }
            Request::FindContent(FindContent { content_key }) => match self.db.get(&content_key) {
                Ok(Some(value)) => {
                    let empty_enrs: Vec<SszEnr> = vec![];
                    Response::FoundContent(FoundContent {
                        enrs: empty_enrs,
                        payload: value,
                    })
                }
                Ok(None) => {
                    let enrs = self.overlay.find_nodes_close_to_content(content_key);
                    let empty_payload: Vec<u8> = vec![];
                    Response::FoundContent(FoundContent {
                        enrs: enrs,
                        payload: empty_payload,
                    })
                }
                Err(e) => panic!("Unable to respond to FindContent: {}", e),
            },
        };

        Ok(response)
    }
}

impl PortalnetProtocol {
    pub async fn new(
        portal_config: PortalnetConfig,
        jsonrpc_rx: mpsc::UnboundedReceiver<PortalEndpoint>,
    ) -> Result<(Self, PortalnetEvents, JsonRpcHandler), String> {
        let listen_all_ips = SocketAddr::new("0.0.0.0".parse().unwrap(), portal_config.listen_port);

        let external_addr = portal_config
            .external_addr
            .or_else(|| socket::stun_for_external(&listen_all_ips))
            .unwrap_or_else(|| socket::default_local_address(portal_config.listen_port));

        let config = DiscoveryConfig {
            discv5_config: Discv5ConfigBuilder::default().build(),
            // This is for defining the ENR:
            listen_port: external_addr.port(),
            listen_address: external_addr.ip(),
            bootnode_enrs: portal_config.bootnode_enrs,
            private_key: portal_config.private_key,
            ..Default::default()
        };

        let mut discovery = Discovery::new(config).unwrap();
        discovery.start(listen_all_ips).await?;

        let protocol_receiver = discovery
            .discv5
            .event_stream()
            .await
            .map_err(|e| e.to_string())?;

        let overlay = Overlay::new(
            discovery.local_enr(),
            portal_config.data_radius,
            OverlayConfig::default(),
        );

        let discovery = Arc::new(discovery);

        let proto = Self {
            discovery: discovery.clone(),
            overlay: overlay.clone(),
        };

        let data_path = get_data_dir();

        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        let db = DB::open(&db_opts, data_path).unwrap();

        let events = PortalnetEvents {
            discovery: discovery.clone(),
            overlay: overlay.clone(),
            protocol_receiver,
            db,
        };

        let rpc_handler = JsonRpcHandler {
            discovery,
            jsonrpc_rx,
        };

        Ok((proto, events, rpc_handler))
    }

    pub async fn send_ping(&self, data_radius: U256, enr: Enr) -> Result<Vec<u8>, String> {
        let enr_seq = self.discovery.local_enr().seq();
        let msg = Ping {
            enr_seq,
            data_radius,
        };
        self.discovery
            .send_talkreq(
                enr,
                PROTOCOL.to_string(),
                Message::Request(Request::Ping(msg)).to_bytes(),
            )
            .await
    }

    pub async fn send_find_nodes(&self, distances: Vec<u16>, enr: Enr) -> Result<Vec<u8>, String> {
        let msg = FindNodes { distances };
        self.discovery
            .send_talkreq(
                enr,
                PROTOCOL.to_string(),
                Message::Request(Request::FindNodes(msg)).to_bytes(),
            )
            .await
    }

    pub async fn send_find_content(
        &self,
        content_key: Vec<u8>,
        enr: Enr,
    ) -> Result<Vec<u8>, String> {
        let msg = FindContent { content_key };
        self.discovery
            .send_talkreq(
                enr,
                PROTOCOL.to_string(),
                Message::Request(Request::FindContent(msg)).to_bytes(),
            )
            .await
    }

    /// Convenience call for testing, quick way to ping bootnodes
    pub async fn ping_bootnodes(&mut self) -> Result<(), String> {
        // Trigger bonding with bootnodes, at both the base layer and portal overlay.
        // The overlay ping via talkreq will trigger a session at the base layer, then
        // a session on the (overlay) portal network.
        for enr in self.discovery.discv5.table_entries_enr() {
            debug!("Pinging {} on portal network", enr);
            let ping_result = self.send_ping(U256::from(u64::MAX), enr).await?;
            debug!("Portal network Ping result: {:?}", ping_result);
        }
        Ok(())
    }
}
