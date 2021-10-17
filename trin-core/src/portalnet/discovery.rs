#![allow(dead_code)]

use super::types::{FindNodes, HexData, PortalnetConfig};
use super::Enr;
use crate::portalnet::types::{
    DiscoveryRequestError, Message, MessageDecodeError, Nodes, Request, Response,
};
use crate::socket;
use discv5::enr::{CombinedKey, EnrBuilder, NodeId};
use discv5::{Discv5, Discv5Config, Discv5ConfigBuilder, RequestError, TalkRequest};
use log::{info, warn};
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};

pub const DISCV5_PROTOCOL: &str = "discv5";

#[derive(Clone)]
pub struct Config {
    pub listen_address: IpAddr,
    pub listen_port: u16,
    pub discv5_config: Discv5Config,
    pub bootnode_enrs: Vec<Enr>,
    pub private_key: Option<HexData>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_address: "0.0.0.0".parse().expect("valid ip address"),
            listen_port: 4242,
            discv5_config: Discv5Config::default(),
            bootnode_enrs: vec![],
            private_key: None,
        }
    }
}

pub type ProtocolRequest = Vec<u8>;

/// Base Node Discovery Protocol v5 layer
pub struct Discovery {
    pub discv5: Discv5,
    /// Indicates if the discv5 service has been started
    pub started: bool,
    pub listen_socket: SocketAddr,
}

impl Discovery {
    pub fn new(portal_config: PortalnetConfig) -> Result<Self, String> {
        let listen_all_ips = SocketAddr::new("0.0.0.0".parse().unwrap(), portal_config.listen_port);

        let external_addr = portal_config
            .external_addr
            .or_else(|| socket::stun_for_external(&listen_all_ips))
            .unwrap_or_else(|| socket::default_local_address(portal_config.listen_port));

        let config = Config {
            discv5_config: Discv5ConfigBuilder::default().build(),
            // This is for defining the ENR:
            listen_port: external_addr.port(),
            listen_address: external_addr.ip(),
            bootnode_enrs: portal_config.bootnode_enrs,
            private_key: portal_config.private_key,
            ..Default::default()
        };

        let enr_key = match config.private_key {
            Some(val) => CombinedKey::secp256k1_from_bytes(val.0.clone().as_mut_slice()).unwrap(),
            None => CombinedKey::generate_secp256k1(),
        };

        let enr = {
            let mut builder = EnrBuilder::new("v4");
            builder.ip(config.listen_address);
            builder.udp(config.listen_port);
            builder.build(&enr_key).unwrap()
        };

        info!(
            "Starting discv5 with local enr encoded={:?} decoded={}",
            enr, enr
        );

        let mut discv5 = Discv5::new(enr, enr_key, config.discv5_config)
            .map_err(|e| format!("Failed to create discv5 instance: {}", e))?;

        for enr in config.bootnode_enrs {
            info!("Adding bootnode {}", enr);
            discv5
                .add_enr(enr)
                .map_err(|e| format!("Failed to add enr: {}", e))?;
        }

        Ok(Self {
            discv5,
            started: false,
            listen_socket: listen_all_ips,
        })
    }

    pub async fn start(&mut self) -> Result<(), String> {
        let _ = self
            .discv5
            .start(self.listen_socket)
            .await
            .map_err(|e| format!("Failed to start discv5 server: {:?}", e))?;
        self.started = true;
        Ok(())
    }

    /// Returns number of connected peers in the dht
    pub fn connected_peers_len(&self) -> usize {
        self.discv5.connected_peers()
    }

    /// Returns ENR and nodeId information of the local discv5 node
    pub fn node_info(&self) -> Value {
        json!({
            "enr":  self.discv5.local_enr().to_base64(),
            "nodeId":  self.discv5.local_enr().node_id().to_string()
        })
    }

    /// Returns vector of all ENR node IDs of nodes currently contained in the routing table mapped to JSON Value.
    pub fn routing_table_info(&mut self) -> Value {
        let buckets: Vec<(String, String, String)> = self
            .discv5
            .table_entries()
            .iter()
            .map(|(node_id, enr, node_status)| {
                (
                    node_id.to_string(),
                    enr.to_base64(),
                    format!("{:?}", node_status.state),
                )
            })
            .collect();

        json!(
            {
                "localKey": self.discv5.local_enr().node_id().to_string(),
                "buckets": buckets
            }
        )
    }

    pub async fn find_nodes(&self, enr: Enr, distances: Vec<u16>) -> Result<Vec<u8>, RequestError> {
        let msg = FindNodes { distances };

        Ok(self
            .send_talkreq(
                enr,
                DISCV5_PROTOCOL.to_owned(),
                Message::Request(Request::FindNodes(msg)).to_bytes(),
            )
            .await?)
    }

    pub fn connected_peers(&mut self) -> Vec<NodeId> {
        self.discv5.table_entries_id()
    }

    pub fn local_enr(&self) -> Enr {
        self.discv5.local_enr()
    }

    /// Do a FindNode query and add the discovered peers to the dht
    pub async fn discover_nodes(&mut self) -> Result<(), String> {
        let random_node = NodeId::random();
        let nodes = self
            .discv5
            .find_node(random_node)
            .await
            .map_err(|e| format!("FindNode query failed: {:?}", e))?;

        info!("FindNode query found {} nodes", nodes.len());

        for node in nodes {
            self.discv5
                .add_enr(node)
                .map_err(|e| format!("Failed to add node to dht: {}", e))?;
        }
        Ok(())
    }

    pub async fn send_talkreq(
        &self,
        enr: Enr,
        protocol: String,
        request: ProtocolRequest,
    ) -> Result<Vec<u8>, RequestError> {
        let response = self
            .discv5
            .talk_req(enr, protocol.into_bytes(), request)
            .await?;
        Ok(response)
    }

    /// Process base layer discv5 RPC requests
    pub async fn process_rpc_request(&self, talk_request: TalkRequest) {
        let message: Result<Request, MessageDecodeError> =
            match Message::from_bytes(talk_request.body()) {
                Ok(Message::Request(r)) => Ok(r),
                Ok(_) => Err(MessageDecodeError::Type),
                Err(e) => {
                    warn!("{:?}", e);
                    Err(e)
                }
            };

        let response: Result<Response, DiscoveryRequestError> = match &message {
            Ok(Request::FindNodes(FindNodes { distances })) => {
                let distances64: Vec<u64> = distances.iter().map(|x| (*x).into()).collect();
                let enrs = self.discv5.nodes_by_distance(distances64);
                Ok(Response::Nodes(Nodes {
                    // from spec: total = The total number of Nodes response messages being sent.
                    // TODO: support returning multiple messages
                    total: 1_u8,
                    enrs,
                }))
            }
            _ => Err(DiscoveryRequestError::InvalidMessage),
        };

        let reply: Result<Vec<u8>, DiscoveryRequestError> = match response {
            Ok(r) => Ok(Message::Response(r).to_bytes()),
            Err(e) => Err(e),
        };

        match reply {
            Ok(reply) => {
                if let Err(e) = talk_request.respond(reply) {
                    warn!("Failed to send discv5 reply: {}", e);
                }
            }
            Err(e) => warn!("{:?}", e),
        }
    }
}
