use std::{env, net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};

use alloy::primitives::B256;
use clap::Parser;
use ethportal_api::{
    types::{network::Subnetwork, portal_wire::NetworkSpec},
    Enr,
};
use portalnet::{
    constants::{DEFAULT_DISCOVERY_PORT, DEFAULT_NETWORK, DEFAULT_WEB3_HTTP_PORT},
    discovery::ENR_PORTAL_CLIENT_KEY,
};
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client, IntoUrl, Request, Response,
};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware, RequestBuilder};
use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};
use tokio::time::Duration;
use tracing::error;
use trin_utils::cli::{check_private_key_length, network_parser};
use url::Url;

use crate::{
    census::ENR_OFFER_LIMIT,
    constants::{DEFAULT_GOSSIP_LIMIT, DEFAULT_OFFER_LIMIT, DEFAULT_TOTAL_REQUEST_TIMEOUT},
    types::mode::BridgeMode,
    DEFAULT_BASE_CL_ENDPOINT, DEFAULT_BASE_EL_ENDPOINT, FALLBACK_BASE_CL_ENDPOINT,
    FALLBACK_BASE_EL_ENDPOINT,
};

const DEFAULT_SUBNETWORK: &str = "history";
const DEFAULT_EXECUTABLE_PATH: &str = "./target/debug/trin";
const DEFAULT_EPOCH_ACC_PATH: &str = "./portal-accumulators";

#[derive(Parser, Debug, Clone)]
#[command(name = "Trin Bridge", about = "Feed the network")]
pub struct BridgeConfig {
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
        long = "portal-subnetworks",
        help = "Comma-separated list of which portal subnetworks to activate",
        default_value = DEFAULT_SUBNETWORK,
        value_parser = subnetwork_parser,
    )]
    pub portal_subnetworks: Arc<Vec<Subnetwork>>,

    #[arg(
            long = "network",
                help = "Choose mainnet or angelfood",
                default_value = DEFAULT_NETWORK,
                value_parser = network_parser
            )]
    pub network: Arc<NetworkSpec>,

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

    #[arg(
        long = "private-key",
        value_parser = check_private_key_length,
        help = "Hex encoded 32 byte private key (with 0x prefix)",
        default_value_t = B256::random(),
    )]
    pub private_key: B256,

    #[arg(
        long = "el-provider",
        default_value = DEFAULT_BASE_EL_ENDPOINT,
        help = "Data provider for execution layer data. (pandaops url / infura url with api key / local node url)",
    )]
    pub el_provider: Url,

    #[arg(
        long = "el-provider-fallback",
        default_value = FALLBACK_BASE_EL_ENDPOINT,
        help = "Data provider for execution layer data. (pandaops url / infura url with api key / local node url)",
    )]
    pub el_provider_fallback: Url,

    #[arg(
        long = "cl-provider",
        default_value = DEFAULT_BASE_CL_ENDPOINT,
        help = "Data provider for consensus layer data. (pandaops url / local node url)",
    )]
    pub cl_provider: Url,

    #[arg(
        long = "cl-provider-fallback",
        default_value = FALLBACK_BASE_CL_ENDPOINT,
        help = "Data provider for consensus layer data. (pandaops url / local node url)",
    )]
    pub cl_provider_fallback: Url,

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

    #[arg(
        default_value_t = DEFAULT_OFFER_LIMIT,
        long = "offer-limit",
        help = "The maximum number of concurrent offer rpc requests. (STATE BRIDGE ONLY)"
    )]
    pub offer_limit: usize,

    #[arg(
        default_value_t = ENR_OFFER_LIMIT,
        long = "enr-offer-limit",
        help = "The maximum number of enrs to gossip per content key (STATE BRIDGE ONLY)."
    )]
    pub enr_offer_limit: usize,

    #[arg(
        long = "filter-clients",
        help = "Filter clients out from offer request (STATE BRIDGE ONLY).",
        value_delimiter = ','
    )]
    pub filter_clients: Vec<ClientType>,

    #[arg(
        default_value_t = DEFAULT_TOTAL_REQUEST_TIMEOUT,
        long = "request-timeout",
        help = "The timeout in seconds is applied from when the request starts connecting until the response body has finished. Also considered a total deadline.",
    )]
    pub request_timeout: u64,

    #[arg(
        help = "Bridge identifier: 'bridge_id/bridge_total' eg. '1/4' (STATE BRIDGE ONLY)",
        long = "bridge-id",
        default_value = "1/1"
    )]
    pub bridge_id: BridgeId,

    #[arg(
        long,
        help = "The directory for storing trin-execution data, useful for storing state in non standard locations."
    )]
    pub data_dir: Option<PathBuf>,
}

/// Used to identify the bridge amongst a set of bridges,
/// each responsible for offering a subset of the total content.
#[derive(Parser, Debug, Clone)]
pub struct BridgeId {
    // must be greater than 0
    pub id: u64,
    // must be greater than 0
    pub total: u64,
}

impl BridgeId {
    // Returns true if the bridge is responsible for gossiping the content
    // at the given index. Each bridge is responsible for gossiping 1/n of
    // the total content, where n is the total number of bridges.
    pub fn is_selected(&self, index: u64) -> bool {
        if self.total == 1 {
            return true;
        }
        // offset bridge id by 1 to be compatible with modulo operation
        index % self.total == (self.id - 1)
    }
}

impl FromStr for BridgeId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 2 {
            return Err("Invalid bridge id format".to_string());
        }
        let id = parts[0]
            .parse()
            .map_err(|_| "Invalid bridge id".to_string())?;
        let total = parts[1]
            .parse()
            .map_err(|_| "Invalid bridge total".to_string())?;
        if id > total {
            return Err("Bridge id must be less than or equal to total".to_string());
        }
        if id == 0 || total == 0 {
            return Err("Bridge id and total must each be greater than 0".to_string());
        }
        Ok(Self { id, total })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientType {
    Fluffy,
    Trin,
    Shisui,
    Ultralight,
    Unknown,
}

impl FromStr for ClientType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "fluffy" => Ok(ClientType::Fluffy),
            "trin" => Ok(ClientType::Trin),
            "shisui" => Ok(ClientType::Shisui),
            "ultralight" => Ok(ClientType::Ultralight),
            "unknown" => Ok(ClientType::Unknown),
            _ => Err(format!("Unknown client type: {s}")),
        }
    }
}

impl From<&Enr> for ClientType {
    fn from(enr: &Enr) -> Self {
        let client_id = enr
            .get_decodable::<String>(ENR_PORTAL_CLIENT_KEY)
            .and_then(|v| v.ok());
        if let Some(client_id) = client_id {
            if client_id.starts_with("t") {
                ClientType::Trin
            } else if client_id.starts_with("f") {
                ClientType::Fluffy
            } else if client_id.starts_with("s") {
                ClientType::Shisui
            } else if client_id.starts_with("u") {
                ClientType::Ultralight
            } else {
                ClientType::Unknown
            }
        } else {
            ClientType::Unknown
        }
    }
}

pub fn url_to_client(url: Url, request_timeout: u64) -> Result<ClientWithBaseUrl, String> {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    if let Some(host) = url.host_str() {
        if host.contains("pandaops.io") {
            let client_id = env::var("PANDAOPS_CLIENT_ID").unwrap_or_else(|_| {
                error!("Pandaops provider detected without PANDAOPS_CLIENT_ID set");
                "null".to_string()
            });

            let client_secret = env::var("PANDAOPS_CLIENT_SECRET").unwrap_or_else(|_| {
                error!("Pandaops provider detected without PANDAOPS_CLIENT_SECRET set");
                "null".to_string()
            });

            headers.insert(
                "CF-Access-Client-Id",
                HeaderValue::from_str(&client_id).map_err(|_| "Invalid client id header value")?,
            );

            headers.insert(
                "CF-Access-Client-Secret",
                HeaderValue::from_str(&client_secret)
                    .map_err(|_| "Invalid client secret header value")?,
            );
        }
    } else {
        return Err("Failed to find host string".into());
    }

    // Add retry middleware
    let reqwest_client = Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(request_timeout))
        .build()
        .map_err(|_| "Failed to build HTTP client")?;
    let client = ClientBuilder::new(reqwest_client)
        .with(RetryTransientMiddleware::new_with_policy(
            ExponentialBackoff::builder().build_with_max_retries(3),
        ))
        .build();
    let client_with_base_url = ClientWithBaseUrl::new(client, url);

    Ok(client_with_base_url)
}

pub struct ClientWithBaseUrl {
    client: ClientWithMiddleware,
    base_url: Url,
}

impl ClientWithBaseUrl {
    pub fn new(client: ClientWithMiddleware, base_url: Url) -> Self {
        Self { client, base_url }
    }

    pub fn client(&self) -> &ClientWithMiddleware {
        &self.client
    }

    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    pub fn get<U: IntoUrl>(&self, url: U) -> anyhow::Result<RequestBuilder> {
        let url = self.base_url.join(url.as_str())?;
        Ok(self.client.get(url))
    }

    pub fn post<U: IntoUrl>(&self, url: U) -> anyhow::Result<RequestBuilder> {
        let url = self.base_url.join(url.as_str())?;
        Ok(self.client.post(url))
    }

    pub async fn execute(&self, request: Request) -> Result<Response, reqwest_middleware::Error> {
        self.client.execute(request).await
    }
}

// parser for subnetworks, makes sure that the state network is not ran alongside other subnetworks
fn subnetwork_parser(subnetwork_string: &str) -> Result<Arc<Vec<Subnetwork>>, String> {
    let active_subnetworks: Vec<Subnetwork> = subnetwork_string
        .split(',')
        .map(Subnetwork::from_str)
        .collect::<Result<Vec<Subnetwork>, String>>()?;
    if active_subnetworks.contains(&Subnetwork::State) && active_subnetworks.len() > 1 {
        return Err("The State network doesn't support being ran with other subnetwork bridges at the same time".to_string());
    }
    Ok(Arc::new(active_subnetworks))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::types::mode::ModeType;

    #[test]
    fn test_default_bridge_config() {
        const EXECUTABLE_PATH: &str = "path/to/executable";
        const EPOCH_ACC_PATH: &str = "path/to/epoch/accumulator";
        let bridge_config = BridgeConfig::parse_from([
            "bridge",
            "--executable-path",
            EXECUTABLE_PATH,
            "--epoch-accumulator-path",
            EPOCH_ACC_PATH,
            "--portal-subnetworks",
            "history,beacon",
        ]);
        assert_eq!(
            bridge_config.executable_path,
            PathBuf::from(EXECUTABLE_PATH)
        );
        assert_eq!(bridge_config.mode, BridgeMode::Latest);
        assert_eq!(bridge_config.epoch_acc_path, PathBuf::from(EPOCH_ACC_PATH));
        assert_eq!(
            bridge_config.el_provider.to_string(),
            DEFAULT_BASE_EL_ENDPOINT
        );
        assert_eq!(
            bridge_config.el_provider_fallback.to_string(),
            FALLBACK_BASE_EL_ENDPOINT
        );
        assert_eq!(
            bridge_config.cl_provider.to_string(),
            DEFAULT_BASE_CL_ENDPOINT
        );
        assert_eq!(
            bridge_config.cl_provider_fallback.to_string(),
            FALLBACK_BASE_CL_ENDPOINT
        );
        assert_eq!(
            bridge_config.portal_subnetworks,
            vec![Subnetwork::History, Subnetwork::Beacon].into()
        );
    }

    #[test]
    fn test_bridge_config_with_epoch() {
        const EXECUTABLE_PATH: &str = "path/to/executable";
        const EPOCH_ACC_PATH: &str = "path/to/epoch/accumulator";
        const EPOCH: &str = "backfill:e100";
        let bridge_config = BridgeConfig::parse_from([
            "bridge",
            "--executable-path",
            EXECUTABLE_PATH,
            "--epoch-accumulator-path",
            EPOCH_ACC_PATH,
            "--mode",
            EPOCH,
        ]);
        assert_eq!(
            bridge_config.executable_path,
            PathBuf::from(EXECUTABLE_PATH)
        );
        assert_eq!(
            bridge_config.mode,
            BridgeMode::Backfill(ModeType::Epoch(100))
        );
        assert_eq!(bridge_config.epoch_acc_path, PathBuf::from(EPOCH_ACC_PATH));
        assert_eq!(
            bridge_config.portal_subnetworks,
            vec![Subnetwork::History].into()
        );
    }

    #[test]
    #[should_panic(expected = "Unknown subnetwork: das")]
    fn test_invalid_network_arg() {
        BridgeConfig::try_parse_from(["bridge", "--portal-subnetworks", "das"].iter()).unwrap();
    }
}
