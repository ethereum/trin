#![allow(dead_code)]

use super::types::{HexData, PortalnetConfig};
use super::Enr;
use crate::portalnet::types::ProtocolId;
use crate::socket;
use discv5::enr::{CombinedKey, EnrBuilder, NodeId};
use discv5::{Discv5, Discv5Config, Discv5ConfigBuilder, RequestError};
use log::info;
use serde_json::{json, Value};
use std::convert::TryFrom;
use std::net::{IpAddr, SocketAddr};

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

        let ip_addr = if portal_config.internal_ip {
            socket::default_local_address(portal_config.listen_port)
        } else {
            portal_config
                .external_addr
                .or_else(|| socket::stun_for_external(&listen_all_ips))
                .unwrap_or_else(|| socket::default_local_address(portal_config.listen_port))
        };

        let config = Config {
            discv5_config: Discv5ConfigBuilder::default().build(),
            // This is for defining the ENR:
            listen_port: ip_addr.port(),
            listen_address: ip_addr.ip(),
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
        protocol: ProtocolId,
        request: ProtocolRequest,
    ) -> Result<Vec<u8>, RequestError> {
        // Send empty protocol id if unable to convert it to bytes
        let protocol = Vec::try_from(protocol).unwrap_or(vec![]);

        let response = self.discv5.talk_req(enr, protocol, request).await?;
        Ok(response)
    }
}
