use std::{env, net::SocketAddr, path::PathBuf, str::FromStr};

use alloy_primitives::B256;
use clap::{Parser, Subcommand};
use surf::{
    middleware::{Middleware, Next},
    Body, Client, Config, Request, Response,
};
use tokio::{
    process::Child,
    time::{sleep, Duration},
};
use tracing::{error, warn};
use url::Url;

use crate::{
    client_handles::{fluffy_handle, trin_handle},
    constants::{DEFAULT_GOSSIP_LIMIT, HTTP_REQUEST_TIMEOUT},
    types::{mode::BridgeMode, network::NetworkKind},
    DEFAULT_BASE_CL_ENDPOINT, DEFAULT_BASE_EL_ENDPOINT, FALLBACK_BASE_CL_ENDPOINT,
    FALLBACK_BASE_EL_ENDPOINT,
};
use ethportal_api::types::cli::{
    check_private_key_length, DEFAULT_DISCOVERY_PORT, DEFAULT_WEB3_HTTP_PORT,
};

// max value of 16 b/c...
// - reliably calculate spaced private keys in a reasonable time
// - for values b/w 16 - 256, calculated spaced private keys are less and less evenly spread
// - running more than 16 nodes simultaneously is not thoroughly tested
pub const MAX_NODE_COUNT: u8 = 16;
const DEFAULT_SUBNETWORK: &str = "history";
const DEFAULT_EXECUTABLE_PATH: &str = "./target/debug/trin";
const DEFAULT_EPOCH_ACC_PATH: &str = "./portal-accumulators";

#[derive(Parser, Debug, Clone)]
#[command(name = "Trin Bridge", about = "Feed the network")]
pub struct BridgeConfig {
    #[arg(
        long,
        help = "number of nodes to launch - must be between 1 and 16",
        default_value = "1",
        value_parser = check_node_count
    )]
    pub node_count: u8,

    #[arg(long, help = "path to portalnet client executable", default_value = DEFAULT_EXECUTABLE_PATH)]
    pub executable_path: PathBuf,

    #[arg(
        long,
        default_value = "latest",
        help = "['latest', 'backfill', <u64> to provide the starting epoch]"
    )]
    pub mode: BridgeMode,

    #[arg(
        long = "epoch-accumulator-path",
        help = "Path to epoch accumulator repo for bridge mode",
        default_value = DEFAULT_EPOCH_ACC_PATH
    )]
    pub epoch_acc_path: PathBuf,

    #[arg(
        long = "network",
        help = "Comma-separated list of which portal subnetworks to activate",
        default_value = DEFAULT_SUBNETWORK,
        use_value_delimiter = true
    )]
    pub network: Vec<NetworkKind>,

    #[arg(
        long,
        help = "Socket address for bridge metrics reporting, ex: 127.0.0.1:9091"
    )]
    pub metrics_url: Option<SocketAddr>,

    #[arg(
        long,
        help = "Socket address for client metrics reporting, ex: 127.0.0.1:9090"
    )]
    pub client_metrics_url: Option<SocketAddr>,

    #[arg(
        default_value = "default",
        long = "bootnodes",
        help = "One or more comma-delimited base64-encoded ENR's or multiaddr strings of peers to initially add to the local routing table"
    )]
    pub bootnodes: String,

    #[arg(
        long = "external-ip",
        help = "(Only use this if you are behind a NAT) The address which will be advertised to peers (in an ENR). Changing it does not change which address trin binds to, ex: 127.0.0.1"
    )]
    pub external_ip: Option<String>,

    #[command(subcommand)]
    pub client_type: ClientType,

    #[arg(
        long = "root-private-key",
        value_parser = check_private_key_length,
        help = "Hex encoded 32 byte private key (with 0x prefix) (used as the root key for generating spaced private keys, if multiple nodes are selected)"
    )]
    pub root_private_key: Option<B256>,

    #[arg(
        long = "el-provider",
        default_value = DEFAULT_BASE_EL_ENDPOINT,
        help = "Data provider for execution layer data. (pandaops url / infura url with api key / local node url)",
        value_parser = url_to_client
    )]
    pub el_provider: Client,

    #[arg(
        long = "el-provider-fallback",
        default_value = FALLBACK_BASE_EL_ENDPOINT,
        help = "Data provider for execution layer data. (pandaops url / infura url with api key / local node url)",
        value_parser = url_to_client
    )]
    pub el_provider_fallback: Client,

    #[arg(
        long = "cl-provider",
        default_value = DEFAULT_BASE_CL_ENDPOINT,
        help = "Data provider for consensus layer data. (pandaops url / local node url)",
        value_parser = url_to_client
    )]
    pub cl_provider: Client,

    #[arg(
        long = "cl-provider-fallback",
        default_value = FALLBACK_BASE_CL_ENDPOINT,
        help = "Data provider for consensus layer data. (pandaops url / local node url)",
        value_parser = url_to_client
    )]
    pub cl_provider_fallback: Client,

    #[arg(
        default_value_t = DEFAULT_DISCOVERY_PORT,
        long = "base-discovery-port",
        help = "The UDP port to listen on. If more than one node is launched, the additional ports will be incremented by 1."
    )]
    pub base_discovery_port: u16,

    #[arg(
        default_value_t = DEFAULT_WEB3_HTTP_PORT,
        long = "base-rpc-port",
        help = "The base jsonrpc port to listen on. If more than one node is launched, the additional ports will be incremented by 1."
    )]
    pub base_rpc_port: u16,

    #[arg(
        default_value_t = DEFAULT_GOSSIP_LIMIT,
        long = "gossip-limit",
        help = "The maximum number of active blocks being gossiped."
    )]
    pub gossip_limit: usize,
}

fn check_node_count(val: &str) -> Result<u8, String> {
    let node_count: u8 = val.parse().map_err(|_| "Invalid node count".to_string())?;
    if node_count > 0 && node_count <= MAX_NODE_COUNT {
        Ok(node_count)
    } else {
        Err(format!("Node count must be between 1 and {MAX_NODE_COUNT}"))
    }
}

fn url_to_client(url: &str) -> Result<Client, String> {
    let mut config = Config::new()
        .add_header("Content-Type", "application/json")
        .expect("to be able to add content type header")
        .set_timeout(Some(HTTP_REQUEST_TIMEOUT));
    let url = Url::parse(url).map_err(|_| "Invalid provider url".to_string())?;
    if url
        .host_str()
        .expect("to find host string")
        .contains("pandaops.io")
    {
        let client_id = env::var("PANDAOPS_CLIENT_ID").unwrap_or_else(|_| {
            error!("Pandoaps provider detected without PANDAOPS_CLIENT_ID set");
            "null".to_string()
        });
        let client_secret = env::var("PANDAOPS_CLIENT_SECRET").unwrap_or_else(|_| {
            error!("Pandoaps provider detected without PANDAOPS_CLIENT_SECRET set");
            "null".to_string()
        });
        config = config
            .clone()
            .add_header("CF-Access-Client-Id", client_id)
            .map_err(|_| "to be able to add client id header")?
            .add_header("CF-Access-Client-Secret", client_secret)
            .map_err(|_| "to be able to add client secret header")?
            .set_base_url(url);
    } else {
        config = config.set_base_url(url);
    }
    let client: Client = config
        .try_into()
        .map_err(|_| "to convert config to client")?;
    Ok(client.with(Retry::default()))
}

#[derive(Debug)]
pub struct Retry {
    attempts: u8,
}

impl Retry {
    pub fn new(attempts: u8) -> Self {
        Retry { attempts }
    }
}

#[async_trait::async_trait]
impl Middleware for Retry {
    async fn handle(
        &self,
        mut req: Request,
        client: Client,
        next: Next<'_>,
    ) -> Result<Response, surf::Error> {
        let mut retry_count: u8 = 0;
        let body = req.take_body().into_bytes().await?;
        while retry_count < self.attempts {
            if retry_count > 0 {
                warn!("Retrying request");
            }
            let mut new_req = req.clone();
            new_req.set_body(Body::from_bytes(body.clone()));
            if let Ok(val) = next.run(new_req, client.clone()).await {
                if val.status().is_success() {
                    return Ok(val);
                }
                tracing::error!("Execution client request failed with: {:?}", val);
            };
            retry_count += 1;
            sleep(Duration::from_millis(100)).await;
        }
        Err(surf::Error::from_str(
            500,
            "Unable to fetch batch after 3 retries",
        ))
    }
}

impl Default for Retry {
    fn default() -> Self {
        Self { attempts: 3 }
    }
}

type ParseError = &'static str;

#[derive(Clone, Debug, PartialEq, Eq, Subcommand)]
pub enum ClientType {
    Fluffy,
    Trin,
}

impl FromStr for ClientType {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "fluffy" => Ok(ClientType::Fluffy),
            "trin" => Ok(ClientType::Trin),
            _ => Err("Invalid client type"),
        }
    }
}

impl ClientType {
    pub fn build_handle(
        &self,
        private_key: String,
        rpc_port: u16,
        udp_port: u16,
        bridge_config: BridgeConfig,
    ) -> anyhow::Result<Child> {
        match self {
            ClientType::Fluffy => fluffy_handle(private_key, rpc_port, udp_port, bridge_config),
            ClientType::Trin => trin_handle(private_key, rpc_port, udp_port, bridge_config),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::types::mode::ModeType;

    #[test]
    fn test_default_bridge_config() {
        const NODE_COUNT: &str = "1";
        const EXECUTABLE_PATH: &str = "path/to/executable";
        const EPOCH_ACC_PATH: &str = "path/to/epoch/accumulator";
        let bridge_config = BridgeConfig::parse_from([
            "bridge",
            "--node-count",
            NODE_COUNT,
            "--executable-path",
            EXECUTABLE_PATH,
            "--epoch-accumulator-path",
            EPOCH_ACC_PATH,
            "--network",
            "history,beacon",
            "trin",
        ]);
        assert_eq!(bridge_config.node_count, 1);
        assert_eq!(
            bridge_config.executable_path,
            PathBuf::from(EXECUTABLE_PATH)
        );
        assert_eq!(bridge_config.mode, BridgeMode::Latest);
        assert_eq!(bridge_config.epoch_acc_path, PathBuf::from(EPOCH_ACC_PATH));
        assert!(bridge_config
            .el_provider
            .config()
            .base_url
            .as_ref()
            .unwrap()
            .as_str()
            .contains(DEFAULT_BASE_EL_ENDPOINT));
        assert!(bridge_config
            .el_provider_fallback
            .config()
            .base_url
            .as_ref()
            .unwrap()
            .as_str()
            .contains(FALLBACK_BASE_EL_ENDPOINT));
        assert!(bridge_config
            .cl_provider
            .config()
            .base_url
            .as_ref()
            .unwrap()
            .as_str()
            .contains(DEFAULT_BASE_CL_ENDPOINT));
        assert!(bridge_config
            .cl_provider_fallback
            .config()
            .base_url
            .as_ref()
            .unwrap()
            .as_str()
            .contains(FALLBACK_BASE_CL_ENDPOINT));
        assert_eq!(
            bridge_config.network,
            vec![NetworkKind::History, NetworkKind::Beacon]
        );
    }

    #[test]
    fn test_bridge_config_with_epoch() {
        const NODE_COUNT: &str = "1";
        const EXECUTABLE_PATH: &str = "path/to/executable";
        const EPOCH_ACC_PATH: &str = "path/to/epoch/accumulator";
        const EPOCH: &str = "backfill:e100";
        let bridge_config = BridgeConfig::parse_from([
            "bridge",
            "--node-count",
            NODE_COUNT,
            "--executable-path",
            EXECUTABLE_PATH,
            "--epoch-accumulator-path",
            EPOCH_ACC_PATH,
            "--mode",
            EPOCH,
            "trin",
        ]);
        assert_eq!(bridge_config.node_count, 1);
        assert_eq!(
            bridge_config.executable_path,
            PathBuf::from(EXECUTABLE_PATH)
        );
        assert_eq!(
            bridge_config.mode,
            BridgeMode::Backfill(ModeType::Epoch(100))
        );
        assert_eq!(bridge_config.epoch_acc_path, PathBuf::from(EPOCH_ACC_PATH));
        assert_eq!(bridge_config.network, vec![NetworkKind::History]);
    }

    #[test]
    fn test_bridge_config_with_max_node_count() {
        let node_count_string = MAX_NODE_COUNT.to_string();
        let node_count: &str = node_count_string.as_str();
        const EXECUTABLE_PATH: &str = "path/to/executable";
        const EPOCH_ACC_PATH: &str = "path/to/epoch/accumulator";
        let bridge_config = BridgeConfig::parse_from([
            "bridge",
            "--node-count",
            node_count,
            "--executable-path",
            EXECUTABLE_PATH,
            "--epoch-accumulator-path",
            EPOCH_ACC_PATH,
            "trin",
        ]);
        assert_eq!(bridge_config.node_count, 16);
        assert_eq!(
            bridge_config.executable_path,
            PathBuf::from(EXECUTABLE_PATH)
        );
        assert_eq!(bridge_config.mode, BridgeMode::Latest);
        assert_eq!(bridge_config.epoch_acc_path, PathBuf::from(EPOCH_ACC_PATH));
        assert_eq!(bridge_config.network, vec![NetworkKind::History]);
    }

    #[test]
    #[should_panic(
        expected = "Invalid network arg. Expected either 'beacon', 'history' or 'state'"
    )]
    fn test_invalid_network_arg() {
        BridgeConfig::try_parse_from(["bridge", "--network", "das", "trin"].iter()).unwrap();
    }

    #[test]
    #[should_panic(expected = "MissingSubcommand")]
    fn test_config_requires_client_type_subcommand() {
        BridgeConfig::try_parse_from([
            "bridge",
            "--node-count",
            "1",
            "--executable-path",
            "path/to/executable",
            "--epoch-accumulator-path",
            "path/to/epoch/accumulator",
        ])
        .unwrap();
    }
}
