#![allow(dead_code)]

use super::types::{HexData, SszEnr};
use super::{protocol::PROTOCOL, Enr};
use crate::utils::xor_two_values;
use discv5::enr::{CombinedKey, EnrBuilder, NodeId};
use discv5::{Discv5, Discv5Config};
use log::info;
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

pub struct Discovery {
    pub discv5: Discv5,
    /// Indicates if the discv5 service has been started
    pub started: bool,
}

impl Discovery {
    pub fn new(config: Config) -> Result<Self, String> {
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
        })
    }

    pub async fn start(&mut self, listen_socket: SocketAddr) -> Result<(), String> {
        let _ = self
            .discv5
            .start(listen_socket)
            .await
            .map_err(|e| format!("Failed to start discv5 server: {:?}", e))?;
        self.started = true;
        Ok(())
    }

    /// Returns number of connected peers in the dht
    pub fn connected_peers_len(&self) -> usize {
        self.discv5.connected_peers()
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

    /// Returns closest nodes according to given distances.
    pub fn find_nodes_response(&self, distances: Vec<u64>) -> Vec<Enr> {
        self.discv5.nodes_by_distance(distances)
    }

    /// Returns list of nodes (max 32) closer to content than self, sorted by distance.
    pub fn find_nodes_close_to_content(&self, content_key: Vec<u8>) -> Vec<SszEnr> {
        let self_node_id = self.local_enr().node_id();
        let self_distance = xor_two_values(&content_key, &self_node_id.raw().to_vec());

        let mut nodes_with_distance: Vec<(Vec<u8>, Enr)> = self
            .discv5
            .table_entries_enr()
            .into_iter()
            .map(|enr| {
                (
                    xor_two_values(&content_key, &enr.node_id().raw().to_vec()),
                    enr,
                )
            })
            .collect();

        nodes_with_distance.sort_by(|a, b| a.0.cmp(&b.0));

        let closest_nodes = nodes_with_distance
            .into_iter()
            .take(32)
            .filter(|node_record| &node_record.0 < &self_distance)
            .map(|node_record| SszEnr::new(node_record.1))
            .collect();

        closest_nodes
    }

    pub async fn send_talkreq(
        &self,
        enr: Enr,
        request: ProtocolRequest,
    ) -> Result<Vec<u8>, String> {
        let response = self
            .discv5
            .talk_req(enr, PROTOCOL.as_bytes().to_vec(), request)
            .await
            .map_err(|e| format!("TalkReq query failed: {:?}", e))?;
        Ok(response)
    }
}
