#![allow(dead_code)]

use std::net::SocketAddr;

use super::{
    discovery::{Config as DiscoveryConfig, Discovery},
    types::{FindContent, FindNodes, FoundContent, Nodes, Ping, Pong, Request, Response},
    U256,
};
use super::{types::Message, Enr};
use discv5::{Discv5ConfigBuilder, TalkReqHandler, TalkRequest};
use log::warn;
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct PortalConfig {
    pub listen_port: u16,
    pub bootnode_enrs: Vec<Enr>,
    pub data_radius: U256,
}

impl Default for PortalConfig {
    fn default() -> Self {
        Self {
            listen_port: 4242,
            bootnode_enrs: vec![],
            data_radius: U256::from(u64::MAX), //TODO better data_radius default?
        }
    }
}

pub const PROTOCOL: &str = "portal";

pub struct AlexandriaProtocol {
    discovery: Discovery,
    data_radius: U256,
    protocol_receiver: mpsc::UnboundedReceiver<TalkRequest>,
}

#[derive(Clone)]
pub struct ProtocolHandler {
    protocol_sender: mpsc::UnboundedSender<TalkRequest>,
}

impl TalkReqHandler for ProtocolHandler {
    fn talkreq_response(&self, request: TalkRequest) {
        if self.protocol_sender.send(request).is_err() {
            warn!("sending on disconnected channel");
        }
    }
}

impl AlexandriaProtocol {
    pub async fn new(portal_config: PortalConfig) -> Result<Self, String> {
        let config = DiscoveryConfig {
            discv5_config: Discv5ConfigBuilder::default().build(),
            listen_port: portal_config.listen_port,
            bootnode_enrs: portal_config.bootnode_enrs,
            ..Default::default()
        };

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
            data_radius: portal_config.data_radius,
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
            enr_seq,
            data_radius,
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
            while let Some(request) = self.protocol_receiver.recv().await {
                let reply = match self.process_one_request(&request).await {
                    Ok(r) => Message::Response(r).to_bytes(),
                    Err(e) => e.into_bytes(),
                };

                request.respond(reply);
            }
        };

        handle.spawn(fut);
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
                let enr_seq = self.discovery.local_enr().seq();
                Response::Pong(Pong {
                    enr_seq: enr_seq,
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

        Ok(response)
    }
}
