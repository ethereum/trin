use serde::Serialize;

use crate::config::{utils::bytes_serialize, ChainConfig, Forks};

/// The base configuration for a network.
#[derive(Serialize, Default)]
pub struct BaseConfig {
    pub rpc_port: u16,
    pub consensus_rpc: Option<String>,
    #[serde(
        deserialize_with = "bytes_deserialize",
        serialize_with = "bytes_serialize"
    )]
    pub default_checkpoint: Vec<u8>,
    pub chain: ChainConfig,
    pub forks: Forks,
    pub max_checkpoint_age: u64,
}
