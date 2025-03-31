use std::net::SocketAddr;

use alloy::primitives::B256;
use ethportal_api::types::{enr::Enr, network::Network};

use crate::{bootnodes::Bootnodes, constants::DEFAULT_UTP_TRANSFER_LIMIT};

/// Capacity of the cache for observed `NodeAddress` values.
/// Provides capacity for 1000 nodes, to match Discv5's default session_cache_capacity value.
pub const NODE_ADDR_CACHE_CAPACITY: usize = 1000;

#[derive(Clone)]
pub struct PortalnetConfig {
    pub external_addr: Option<SocketAddr>,
    pub private_key: B256,
    pub listen_port: u16,
    pub bootnodes: Vec<Enr>,
    pub no_stun: bool,
    pub no_upnp: bool,
    pub node_addr_cache_capacity: usize,
    pub disable_poke: bool,
    pub trusted_block_root: Option<B256>,
    // the max number of concurrent utp transfers
    pub utp_transfer_limit: usize,
}

// to be used inside test code only
impl Default for PortalnetConfig {
    fn default() -> Self {
        Self {
            external_addr: None,
            private_key: B256::random(),
            listen_port: 4242,
            bootnodes: Bootnodes::default().to_enrs(Network::Mainnet),
            no_stun: false,
            no_upnp: false,
            node_addr_cache_capacity: NODE_ADDR_CACHE_CAPACITY,
            disable_poke: false,
            trusted_block_root: None,
            utp_transfer_limit: DEFAULT_UTP_TRANSFER_LIMIT,
        }
    }
}
