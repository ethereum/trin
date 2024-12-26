use std::{path::PathBuf, sync::Arc};

use alloy::transports::http::reqwest::Url;
use ethportal_api::types::{cli::Web3TransportType, network::Subnetwork};

pub struct RpcConfig {
    pub portal_subnetworks: Arc<Vec<Subnetwork>>,
    pub web3_transport: Web3TransportType,
    pub web3_ipc_path: PathBuf,
    pub web3_http_address: Url,
    pub ws: bool,
    pub ws_port: u16,
}
