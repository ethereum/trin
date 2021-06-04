#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use super::{
    discovery::{Config as DiscoveryConfig, Discovery},
    types::{FindContent, FindNodes, FoundContent, Nodes, Ping, Pong, Request, Response},
    U256,
};
use super::{types::Message, Enr};
use discv5::{Discv5ConfigBuilder, TalkReqHandler, TalkRequest};
use log::{debug, error, warn};
use tokio::sync::mpsc;

use super::socket;

#[derive(Clone)]
pub struct PortalnetConfig {
    pub listen_port: u16,
    pub bootnode_enrs: Vec<Enr>,
    pub data_radius: U256,
}

impl Default for PortalnetConfig {
    fn default() -> Self {
        Self {
            listen_port: 4242,
            bootnode_enrs: vec![],
            data_radius: U256::from(u64::MAX), //TODO better data_radius default?
        }
    }
}

pub const PROTOCOL: &str = "portal";

pub struct PortalnetProtocol {
    discovery: Arc<Discovery>,
    data_radius: U256,
}

pub struct PortalnetEvents {
    data_radius: U256,
    discovery: Arc<Discovery>,
    protocol_receiver: mpsc::UnboundedReceiver<TalkRequest>,
}

impl PortalnetEvents {
    /// Receives a request from the talkreq handler and sends a response back
    pub async fn process_requests(mut self) {
        while let Some(request) = self.protocol_receiver.recv().await {
            debug!("Got talkreq message {:?}", request);
            let reply = match self.process_one_request(&request).await {
                Ok(r) => Message::Response(r).to_bytes(),
                Err(e) => {
                    error!("failed to process portal event: {}", e);
                    e.into_bytes()
                }
            };

            request.respond(reply);
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
                    data_radius: self.data_radius,
                })
            }

            Request::FindNodes(FindNodes { distances }) => {
                let distances64: Vec<u64> = distances.iter().map(|x| (*x).into()).collect();
                let enrs = self.discovery.find_nodes_response(distances64);
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

impl PortalnetProtocol {
    pub async fn new(portal_config: PortalnetConfig) -> Result<(Self, PortalnetEvents), String> {
        let listen_all_ips = SocketAddr::new("0.0.0.0".parse().unwrap(), portal_config.listen_port);

        let external_addr = socket::stun_for_external(&listen_all_ips)
            .unwrap_or_else(|| socket::default_local_address(portal_config.listen_port));

        let config = DiscoveryConfig {
            discv5_config: Discv5ConfigBuilder::default().build(),
            // This is for defining the ENR:
            listen_port: external_addr.port(),
            listen_address: external_addr.ip(),
            bootnode_enrs: portal_config.bootnode_enrs,
            ..Default::default()
        };

        let mut discovery = Discovery::new(config).unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        let handler = ProtocolHandler {
            protocol_sender: tx,
        };

        discovery
            .start(listen_all_ips, Some(Box::new(handler)))
            .await?;

        let discovery = Arc::new(discovery);

        let proto = Self {
            discovery: discovery.clone(),
            data_radius: portal_config.data_radius,
        };

        let events = PortalnetEvents {
            data_radius: portal_config.data_radius,
            discovery,
            protocol_receiver: rx,
        };

        Ok((proto, events))
    }

    pub async fn send_ping(&self, data_radius: U256, enr: Enr) -> Result<Vec<u8>, String> {
        let enr_seq = self.discovery.local_enr().seq();
        let msg = Ping {
            enr_seq,
            data_radius,
        };
        self.discovery
            .send_talkreq(enr, Message::Request(Request::Ping(msg)).to_bytes())
            .await
    }

    pub async fn send_find_nodes(&self, distances: Vec<u16>, enr: Enr) -> Result<Vec<u8>, String> {
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
