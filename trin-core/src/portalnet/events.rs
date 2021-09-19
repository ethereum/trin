use std::sync::Arc;

use discv5::{Discv5Event, TalkRequest};
use log::{debug, error, warn};
use rocksdb::DB;
use tokio::sync::mpsc;
use tokio::sync::RwLock;

use super::types::Message;
use super::{
    discovery::Discovery,
    types::{FindContent, FindNodes, FoundContent, Nodes, Ping, Pong, Request, Response, SszEnr},
    utp::{UtpListener, UTP_PROTOCOL},
};
use crate::portalnet::overlay::OverlayProtocol;
use std::collections::HashMap;
use std::convert::TryInto;

pub const PROTOCOL: &str = "portal";

pub struct PortalnetEvents {
    pub discovery: Arc<RwLock<Discovery>>,
    pub overlay: Arc<OverlayProtocol>,
    pub protocol_receiver: mpsc::Receiver<Discv5Event>,
    pub db: Arc<DB>,
    pub utp_listener: UtpListener,
}

impl PortalnetEvents {
    pub async fn new(overlay: Arc<OverlayProtocol>, db: Arc<DB>) -> Self {
        let protocol_receiver = overlay
            .discovery
            .write()
            .await
            .discv5
            .event_stream()
            .await
            .map_err(|e| e.to_string())
            .unwrap();

        let utp_listener = UtpListener {
            discovery: Arc::clone(&overlay.discovery),
            utp_connections: HashMap::new(),
        };

        Self {
            discovery: Arc::clone(&overlay.discovery),
            overlay,
            protocol_receiver,
            db,
            utp_listener,
        }
    }

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
                let enr_seq = self.discovery.read().await.local_enr().seq();
                Response::Pong(Pong {
                    enr_seq: enr_seq,
                    data_radius: self.overlay.data_radius().await,
                })
            }
            Request::FindNodes(FindNodes { distances }) => {
                let distances64: Vec<u64> = distances.iter().map(|x| (*x).into()).collect();
                let enrs = self.overlay.nodes_by_distance(distances64).await;
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
                    let enrs = self.overlay.find_nodes_close_to_content(content_key).await;
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
