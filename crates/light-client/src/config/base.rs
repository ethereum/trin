use alloy::primitives::B256;
use serde::Serialize;

use crate::config::{ChainConfig, Forks};

/// The base configuration for a network.
#[derive(Serialize, Default)]
pub struct BaseConfig {
    pub rpc_port: u16,
    pub consensus_rpc: Option<String>,
    pub default_checkpoint: B256,
    pub chain: ChainConfig,
    pub forks: Forks,
    pub max_checkpoint_age: u64,
}
