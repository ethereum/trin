#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use discv5::{Discv5Event, TalkRequest};
use log::{debug, error, warn};
use rocksdb::{DB};
use serde_json::Value;
use tokio::sync::mpsc;

use crate::{jsonrpc::Params};

use super::{
    discovery::Discovery,
    types::{
        FindContent, FindNodes, FoundContent, HexData, Nodes, Ping, Pong, Request, Response, SszEnr,
    },
    utp::{UtpListener, UTP_PROTOCOL},
    U256,
};
use super::{types::Message, Enr};
use std::collections::HashMap;
use std::convert::TryInto;
use crate::portalnet::overlay::OverlayProtocol;

type Responder<T, E> = mpsc::UnboundedSender<Result<T, E>>;

#[derive(Debug)]
pub enum HistoryEndpointKind {
    GetHistoryNetworkData,
}

#[derive(Debug)]
pub struct HistoryNetworkEndpoint {
    pub kind: HistoryEndpointKind,
    pub resp: Responder<Value, String>,
}

#[derive(Debug)]
pub enum StateEndpointKind {
    GetStateNetworkData,
}

#[derive(Debug)]
pub struct StateNetworkEndpoint {
    pub kind: StateEndpointKind,
    pub resp: Responder<Value, String>,
}

#[derive(Debug)]
pub enum PortalEndpointKind {
    DummyHistoryNetworkData,
    DummyStateNetworkData,
    NodeInfo,
    RoutingTableInfo,
}

#[derive(Debug)]
pub struct PortalEndpoint {
    pub kind: PortalEndpointKind,
    pub params: Params,
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

pub struct PortalnetEvents {
    pub discovery: Arc<Discovery>,
    pub overlay: Arc<OverlayProtocol>,
    pub protocol_receiver: mpsc::Receiver<Discv5Event>,
    pub db: DB,
    pub utp_listener: UtpListener,
}

pub struct JsonRpcHandler {
    pub discovery: Arc<Discovery>,
    pub jsonrpc_rx: mpsc::UnboundedReceiver<PortalEndpoint>,
    pub state_tx: Option<mpsc::UnboundedSender<StateNetworkEndpoint>>,
    pub history_tx: Option<mpsc::UnboundedSender<HistoryNetworkEndpoint>>,
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
                DummyHistoryNetworkData => {
                    let response = match self.history_tx.as_ref() {
                        Some(tx) => {
                            proxy_query_to_history_subnet(
                                tx,
                                HistoryEndpointKind::GetHistoryNetworkData,
                            )
                            .await
                        }
                        None => Err("Chain history subnetwork unavailable.".to_string()),
                    };
                    let _ = cmd.resp.send(response);
                }
                DummyStateNetworkData => {
                    let response = match self.state_tx.as_ref() {
                        Some(tx) => {
                            proxy_query_to_state_subnet(tx, StateEndpointKind::GetStateNetworkData)
                                .await
                        }
                        None => Err("State subnetwork unavailable.".to_string()),
                    };
                    let _ = cmd.resp.send(response);
                }
            }
        }
    }
}

async fn proxy_query_to_history_subnet(
    subnet_tx: &mpsc::UnboundedSender<HistoryNetworkEndpoint>,
    msg_kind: HistoryEndpointKind,
) -> Result<Value, String> {
    let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
    let message = HistoryNetworkEndpoint {
        kind: msg_kind,
        resp: resp_tx,
    };
    let _ = subnet_tx.send(message);
    match resp_rx.recv().await {
        Some(val) => match val {
            Ok(result) => Ok(result),
            Err(msg) => Err(format!(
                "Error returned from chain history subnetwork: {:?}",
                msg.to_string()
            )),
        },
        None => Err("No response from chain history subnetwork".to_string()),
    }
}

async fn proxy_query_to_state_subnet(
    subnet_tx: &mpsc::UnboundedSender<StateNetworkEndpoint>,
    msg_kind: StateEndpointKind,
) -> Result<Value, String> {
    let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
    let message = StateNetworkEndpoint {
        kind: msg_kind,
        resp: resp_tx,
    };
    let _ = subnet_tx.send(message);
    match resp_rx.recv().await {
        Some(val) => match val {
            Ok(result) => Ok(result),
            Err(msg) => Err(format!(
                "Error returned from state subnetwork: {:?}",
                msg.to_string()
            )),
        },
        None => Err("No response from state subnetwork".to_string()),
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

            match std::str::from_utf8(request.protocol()) {
                Ok(protocol) => match protocol {
                    PROTOCOL => {
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
                    UTP_PROTOCOL => {
                        self.utp_listener
                            .process_utp_request(request.body(), request.node_id())
                            .await;
                        self.process_utp_byte_stream().await;
                    }
                    _ => {
                        warn!("Non supported protocol : {}", protocol);
                    }
                },
                Err(_) => warn!("Invalid utf8 protocol decode"),
            }
        }
    }

    async fn process_one_request(&self, talk_request: &TalkRequest) -> Result<Response, String> {
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

    // This could be handled in the UtpListener impl, but for consistency with data handling
    // and clarity it can be put here
    async fn process_utp_byte_stream(&mut self) {
        for (_, conn) in self.utp_listener.utp_connections.iter_mut() {
            let received_stream = conn.recv_data_stream.clone();
            if received_stream.is_empty() {
                continue;
            }

            let message_len = u32::from_be_bytes(received_stream[0..4].try_into().unwrap());

            if message_len + 4 >= received_stream.len() as u32 {
                // handle data function(&received_stream[4..(message_len + 4)]

                // Removed the handled data from the buffer
                conn.recv_data_stream = received_stream[((message_len + 4) as usize)..].to_owned();
            }
        }
    }
}

// impl PortalnetProtocol {
//     pub async fn new(
//         mut discovery: Discovery,
//         portal_config: PortalnetConfig,
//     ) -> Result<(Self, PortalnetEvents), String> {
//         let protocol_receiver = discovery
//             .discv5
//             .event_stream()
//             .await
//             .map_err(|e| e.to_string())?;
//
//         let overlay = Overlay::new(
//             discovery.local_enr(),
//             portal_config.data_radius,
//             OverlayConfig::default(),
//         );
//
//         let discovery = Arc::new(discovery);
//         let data_path = get_data_dir(discovery.local_enr());
//
//         let mut db_opts = Options::default();
//         db_opts.create_if_missing(true);
//         let db = DB::open(&db_opts, data_path).unwrap();
//
//         let utp_listener = UtpListener {
//             discovery: discovery.clone(),
//             utp_connections: HashMap::new(),
//         };
//
//         let events = PortalnetEvents {
//             discovery: discovery.clone(),
//             overlay: overlay.clone(),
//             protocol_receiver,
//             db,
//             utp_listener,
//         };
//
//         let proto = Self {
//             discovery: discovery.clone(),
//             overlay: overlay.clone(),
//         };
//
//         Ok((proto, events))
//     }
//
//     pub async fn send_ping(&self, data_radius: U256, enr: Enr) -> Result<Vec<u8>, String> {
//         let enr_seq = self.discovery.local_enr().seq();
//         let msg = Ping {
//             enr_seq,
//             data_radius,
//         };
//         self.discovery
//             .send_talkreq(
//                 enr,
//                 PROTOCOL.to_string(),
//                 Message::Request(Request::Ping(msg)).to_bytes(),
//             )
//             .await
//     }
//
//     pub async fn send_find_nodes(&self, distances: Vec<u16>, enr: Enr) -> Result<Vec<u8>, String> {
//         let msg = FindNodes { distances };
//         self.discovery
//             .send_talkreq(
//                 enr,
//                 PROTOCOL.to_string(),
//                 Message::Request(Request::FindNodes(msg)).to_bytes(),
//             )
//             .await
//     }
//
//     pub async fn send_find_content(
//         &self,
//         content_key: Vec<u8>,
//         enr: Enr,
//     ) -> Result<Vec<u8>, String> {
//         let msg = FindContent { content_key };
//         self.discovery
//             .send_talkreq(
//                 enr,
//                 PROTOCOL.to_string(),
//                 Message::Request(Request::FindContent(msg)).to_bytes(),
//             )
//             .await
//     }
//
//     /// Convenience call for testing, quick way to ping bootnodes
//     pub async fn ping_bootnodes(&mut self) -> Result<(), String> {
//         // Trigger bonding with bootnodes, at both the base layer and portal overlay.
//         // The overlay ping via talkreq will trigger a session at the base layer, then
//         // a session on the (overlay) portal network.
//         for enr in self.discovery.discv5.table_entries_enr() {
//             debug!("Pinging {} on portal network", enr);
//             let ping_result = self.send_ping(U256::from(u64::MAX), enr).await?;
//             debug!("Portal network Ping result: {:?}", ping_result);
//         }
//         Ok(())
//     }
// }
