use std::net::SocketAddr;

use alloy_primitives::B256;
use ethportal_api::types::{
    bootnodes::Bootnodes,
    cli::{TrinConfig, DEFAULT_UTP_TRANSFER_LIMIT},
};

/// Capacity of the cache for observed `NodeAddress` values.
/// Provides capacity for 32 full k-buckets. This capacity will be shared among all active portal
/// subnetworks.
const NODE_ADDR_CACHE_CAPACITY: usize = discv5::kbucket::MAX_NODES_PER_BUCKET * 32;

#[derive(Clone)]
pub struct PortalnetConfig {
    pub external_addr: Option<SocketAddr>,
    pub private_key: B256,
    pub listen_port: u16,
    pub bootnodes: Bootnodes,
    pub internal_ip: bool,
    pub no_stun: bool,
    pub no_upnp: bool,
    pub node_addr_cache_capacity: usize,
    pub disable_poke: bool,
    pub trusted_block_root: Option<String>,
    // the max number of concurrent utp transfers
    pub utp_transfer_limit: usize,
}

impl Default for PortalnetConfig {
    fn default() -> Self {
        Self {
            external_addr: None,
            private_key: B256::random(),
            listen_port: 4242,
            bootnodes: Bootnodes::default(),
            internal_ip: false,
            no_stun: false,
            no_upnp: false,
            node_addr_cache_capacity: NODE_ADDR_CACHE_CAPACITY,
            disable_poke: false,
            trusted_block_root: None,
            utp_transfer_limit: DEFAULT_UTP_TRANSFER_LIMIT,
        }
    }
}

impl PortalnetConfig {
    pub fn new(trin_config: &TrinConfig, private_key: B256) -> Self {
        Self {
            external_addr: trin_config.external_addr,
            private_key,
            listen_port: trin_config.discovery_port,
            no_stun: trin_config.no_stun,
            no_upnp: trin_config.no_upnp,
            bootnodes: trin_config.bootnodes.clone(),
            disable_poke: trin_config.disable_poke,
            trusted_block_root: trin_config.trusted_block_root.clone(),
            utp_transfer_limit: trin_config.utp_transfer_limit,
            ..Default::default()
        }
    }
}
