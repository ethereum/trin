use std::net::SocketAddr;

use super::{
    discovery::{Config as DiscoveryConfig, Discovery},
    types::{FindContent, FindNodes, FoundContent, Nodes, Ping, Pong, Request, Response},
    U256,
};
use super::{types::Message, Enr};
use discv5::{Discv5ConfigBuilder, TalkReqHandler};
use log::warn;
use tokio::sync::mpsc;

pub const PROTOCOL: &str = "state-network";

pub struct AlexandriaProtocol {
    discovery: Discovery,
    data_radius: U256,
    protocol_receiver: mpsc::UnboundedReceiver<(Request, mpsc::Sender<Result<Response, String>>)>,
}

#[derive(Clone)]
pub struct ProtocolHandler {
    protocol_sender: mpsc::UnboundedSender<(Request, mpsc::Sender<Result<Response, String>>)>,
}

impl TalkReqHandler for ProtocolHandler {
    fn talkreq_response(&self, protocol: &[u8], req: &[u8]) -> Vec<u8> {
        if let Ok(protocol) = String::from_utf8(protocol.to_vec()) {
            if protocol != PROTOCOL {
                return "Invalid protocol".as_bytes().to_vec();
            }
            match Message::from_bytes(req) {
                Err(e) => format!("Invalid request: {}", e).as_bytes().to_vec(),
                Ok(msg) => {
                    if let Message::Request(req) = msg {
                        let (tx, mut rx) = mpsc::channel(1);
                        if let Err(_) = self.protocol_sender.send((req, tx)) {
                            return "Internal error".as_bytes().to_vec();
                        }
                        let resp = std::thread::spawn(move || match rx.blocking_recv() {
                            None => "Internal error".as_bytes().to_vec(),
                            Some(r) => match r {
                                Ok(resp) => Message::Response(resp).to_bytes(),
                                Err(e) => format!("Internal error {}", e).as_bytes().to_vec(),
                            },
                        });
                        resp.join().unwrap()
                    } else {
                        "Invalid message".as_bytes().to_vec()
                    }
                }
            }
        } else {
            "Invalid protocol".as_bytes().to_vec()
        }
    }
}

impl AlexandriaProtocol {
    pub async fn new(port: u16, boot_nodes: Vec<Enr>, data_radius: U256) -> Result<Self, String> {
        let disv5_config = Discv5ConfigBuilder::default().build();

        let mut config = DiscoveryConfig::default();
        config.discv5_config = disv5_config;
        config.listen_port = port;
        config.bootnode_enrs = boot_nodes;

        let local_socket = SocketAddr::new(config.listen_address, config.listen_port);

        let mut discovery = Discovery::new(config).unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        let handler = ProtocolHandler {
            protocol_sender: tx,
        };
        discovery
            .start(local_socket, Some(Box::new(handler)))
            .await?;
        Ok(Self {
            discovery,
            data_radius,
            protocol_receiver: rx,
        })
    }

    pub async fn send_ping(
        &self,
        data_radius: U256,
        enr_seq: u32,
        enr: Enr,
    ) -> Result<Vec<u8>, String> {
        let msg = Ping {
            data_radius,
            enr_seq,
        };
        self.discovery
            .send_talkreq(enr, Message::Request(Request::Ping(msg)).to_bytes())
            .await
    }

    pub async fn send_find_nodes(&self, distances: Vec<u64>, enr: Enr) -> Result<Vec<u8>, String> {
        let msg = FindNodes { distances };
        self.discovery
            .send_talkreq(enr, Message::Request(Request::FindNodes(msg)).to_bytes())
            .await
    }

    pub async fn send_find_content(
        &self,
        content_key: Vec<u8>,
        enr: Enr,
    ) -> Result<Vec<u8>, String> {
        let msg = FindContent { content_key };
        self.discovery
            .send_talkreq(enr, Message::Request(Request::FindContent(msg)).to_bytes())
            .await
    }

    /// Receives a request from the talkreq handler and sends a response back
    pub fn process_request(mut self, handle: tokio::runtime::Handle) {
        let fut = async move {
            while let Some((request, channel)) = self.protocol_receiver.recv().await {
                let response = match request {
                    Request::Ping(Ping { .. }) => {
                        let enr_seq = self.discovery.local_enr().seq();
                        Response::Pong(Pong {
                            enr_seq: enr_seq as u32,
                            data_radius: self.data_radius,
                        })
                    }

                    Request::FindNodes(FindNodes { distances }) => {
                        let enrs = self.discovery.find_nodes_response(distances);
                        Response::Nodes(Nodes {
                            total: enrs.len() as u8,
                            enrs,
                        })
                    }
                    // TODO
                    Request::FindContent(FindContent { .. }) => {
                        Response::FoundContent(FoundContent { enrs: vec![] })
                    }
                };
                if let Err(e) = channel.send(Ok(response)).await {
                    warn!("Failed to respond to talkreq channel: {}", e);
                }
            }
        };

        handle.spawn(fut);
    }
}
