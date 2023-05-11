pub mod dashboard;
use clap::{Args, Parser, Subcommand};

use ethportal_api::jsonrpsee::http_client::HttpClientBuilder;
#[cfg(unix)]
use reth_ipc::client::IpcClientBuilder;
use std::path::PathBuf;
use url::Url;

use ethereum_types::H256;
use serde_json::Value;

use dashboard::grafana::{GrafanaAPI, DASHBOARD_TEMPLATES};
use ethportal_api::jsonrpsee::core::client::ClientT;
use ethportal_api::jsonrpsee::core::params::ArrayParams;
use ethportal_api::jsonrpsee::tracing::warn;
use ethportal_api::{BlockBodyKey, BlockHeaderKey, BlockReceiptsKey, HistoryContentKey};
use trin_types::cli::{
    Web3TransportType, DEFAULT_WEB3_HTTP_ADDRESS, DEFAULT_WEB3_IPC_PATH, DEFAULT_WEB3_TRANSPORT,
};
use trin_utils::bytes::hex_encode;

#[derive(Parser, Debug, PartialEq)]
#[command(
    name = "trin-cli",
    version = "0.0.1",
    author = "Ethereum Foundation",
    about = "Portal Network command line utilities"
)]
enum Trin {
    JsonRpc(JsonRpc),
    #[command(subcommand)]
    EncodeKey(EncodeKey),
    CreateDashboard(DashboardConfig),
}

#[derive(Args, Debug, PartialEq)]
#[command(name = "json-rpc", about = "Run JSON-RPC commands against a trin node")]
struct JsonRpc {
    /// Select transport protocol to serve json-rpc endpoint
    #[arg(
        default_value = DEFAULT_WEB3_TRANSPORT,
        long = "web3-transport"
    )]
    pub web3_transport: Web3TransportType,

    /// Address to accept json-rpc http connections
    #[arg(
        default_value = DEFAULT_WEB3_HTTP_ADDRESS,
        long = "web3-http-address"
    )]
    pub web3_http_address: Url,

    /// IPC path of target JSON-RPC endpoint.
    #[arg(
        default_value = DEFAULT_WEB3_IPC_PATH,
        long = "web3-ipc-path"
    )]
    pub web3_ipc_path: PathBuf,

    /// JSON-RPC method (e.g. discv5_routingTableInfo).
    #[arg(required = true)]
    endpoint: String,

    /// Comma-separated list of JSON-RPC parameters.
    #[arg(long, value_delimiter = ',')]
    params: Option<Vec<String>>,
}

// TODO: Remove clippy allow once a variant with non-"Block" prefix is added.
/// Encode a content key.
#[derive(Subcommand, Debug, PartialEq)]
#[allow(clippy::enum_variant_names)]
enum EncodeKey {
    /// Encode the content key for a block header.
    BlockHeader {
        /// Hex-encoded block hash (omit '0x' prefix).
        #[arg(long)]
        block_hash: H256,
    },
    /// Encode the content key for a block body.
    BlockBody {
        /// Hex-encoded block hash (omit '0x' prefix).
        #[arg(long)]
        block_hash: H256,
    },
    /// Encode the content key for a block's transaction receipts.
    BlockReceipts {
        /// Hex-encoded block hash (omit '0x' prefix).
        #[arg(long)]
        block_hash: H256,
    },
}

#[derive(Args, Debug, PartialEq)]
#[command(name = "create-dashboard")]
#[allow(clippy::enum_variant_names)]
struct DashboardConfig {
    #[arg(default_value = "http://localhost:3000")]
    grafana_address: String,

    #[arg(default_value = "admin")]
    grafana_username: String,

    #[arg(default_value = "admin")]
    grafana_password: String,

    #[arg(default_value = "http://host.docker.internal:9090")]
    prometheus_address: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Trin::parse() {
        Trin::JsonRpc(rpc) => json_rpc(rpc).await,
        Trin::EncodeKey(content_key) => encode_content_key(content_key),
        Trin::CreateDashboard(dashboard_config) => create_dashboard(dashboard_config),
    }
}

fn param_builder(rpc_params: Option<Vec<String>>) -> ArrayParams {
    let mut params = ArrayParams::new();
    if let Some(rpc_params) = rpc_params {
        for i in rpc_params.into_iter() {
            if let Err(err) = params.insert(i) {
                warn!("Failed to serialize params {}", err);
            };
        }
    }
    params
}

async fn json_rpc(rpc: JsonRpc) -> Result<(), Box<dyn std::error::Error>> {
    match rpc.web3_transport {
        Web3TransportType::HTTP => {
            let params = param_builder(rpc.params);
            eprintln!(
                "Attempting RPC. endpoint={} params={:?} http_address={}",
                rpc.endpoint, params, rpc.web3_http_address
            );
            let client = HttpClientBuilder::default().build(rpc.web3_http_address)?;

            let resp: Value = client.request(&rpc.endpoint[..], params).await?;

            println!("{}", serde_json::to_string_pretty(&resp).unwrap());

            Ok(())
        }
        Web3TransportType::IPC => Ok(call_json_rpc_ipc(rpc).await?),
    }
}

#[cfg(unix)]
async fn call_json_rpc_ipc(rpc: JsonRpc) -> Result<(), Box<dyn std::error::Error>> {
    let params = param_builder(rpc.params);
    eprintln!(
        "Attempting RPC. endpoint={} params={:?} file={}",
        rpc.endpoint,
        params,
        rpc.web3_ipc_path.to_string_lossy()
    );
    let client = IpcClientBuilder::default().build(rpc.web3_ipc_path).await?;

    let resp: Value = client.request(&rpc.endpoint[..], params).await?;

    println!("{}", serde_json::to_string_pretty(&resp).unwrap());

    Ok(())
}

#[cfg(windows)]
async fn call_json_rpc_ipc(rpc: JsonRpc) -> Result<(), Box<dyn std::error::Error>> {
    panic!("Windows doesn't support Unix Domain Sockets IPC, use --web3-transport http")
}

fn encode_content_key(content_key: EncodeKey) -> Result<(), Box<dyn std::error::Error>> {
    let key = match content_key {
        EncodeKey::BlockHeader { block_hash } => {
            HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey {
                block_hash: block_hash.into(),
            })
        }
        EncodeKey::BlockBody { block_hash } => HistoryContentKey::BlockBody(BlockBodyKey {
            block_hash: block_hash.into(),
        }),
        EncodeKey::BlockReceipts { block_hash } => {
            HistoryContentKey::BlockReceipts(BlockReceiptsKey {
                block_hash: block_hash.into(),
            })
        }
    };

    println!("{}", hex_encode(Into::<Vec<u8>>::into(key)));

    Ok(())
}

fn create_dashboard(dashboard_config: DashboardConfig) -> Result<(), Box<dyn std::error::Error>> {
    let grafana = GrafanaAPI::new(
        dashboard_config.grafana_username,
        dashboard_config.grafana_password,
        dashboard_config.grafana_address,
    );

    let prometheus_uid = grafana.create_datasource(
        "prometheus".to_string(),
        "prometheus".to_string(),
        dashboard_config.prometheus_address,
    )?;

    // Create a dashboard from each pre-defined template
    for template_path in DASHBOARD_TEMPLATES.iter() {
        let dashboard_url = grafana.create_dashboard(template_path, &prometheus_uid)?;
        println!("Dashboard successfully created: {dashboard_url}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_trin_with_json_rpc() {
        let trin = Trin::parse_from([
            "test",
            "json-rpc",
            "--web3-ipc-path",
            "/tmp/trin.ipc",
            "--params",
            "p1,p2",
            "discv5_routingTableInfo",
        ]);
        assert_eq!(
            trin,
            Trin::JsonRpc(JsonRpc {
                web3_transport: Web3TransportType::IPC,
                endpoint: "discv5_routingTableInfo".to_string(),
                params: Some(vec!["p1".to_string(), "p2".to_string()]),
                web3_ipc_path: PathBuf::from("/tmp/trin.ipc"),
                web3_http_address: url::Url::parse(DEFAULT_WEB3_HTTP_ADDRESS).unwrap(),
            })
        );
    }

    #[test]
    fn test_trin_with_encode_key() {
        const BLOCK_HASH: &str =
            "0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let trin = Trin::parse_from([
            "test",
            "encode-key",
            "block-header",
            "--block-hash",
            BLOCK_HASH,
        ]);
        assert_eq!(
            trin,
            Trin::EncodeKey(EncodeKey::BlockHeader {
                block_hash: H256::from_str(BLOCK_HASH).unwrap()
            })
        );

        let trin = Trin::parse_from([
            "test",
            "encode-key",
            "block-body",
            "--block-hash",
            BLOCK_HASH,
        ]);
        assert_eq!(
            trin,
            Trin::EncodeKey(EncodeKey::BlockBody {
                block_hash: H256::from_str(BLOCK_HASH).unwrap()
            })
        );

        let trin = Trin::parse_from([
            "test",
            "encode-key",
            "block-receipts",
            "--block-hash",
            BLOCK_HASH,
        ]);
        assert_eq!(
            trin,
            Trin::EncodeKey(EncodeKey::BlockReceipts {
                block_hash: H256::from_str(BLOCK_HASH).unwrap()
            })
        );
    }

    #[test]
    fn test_trin_with_create_dashboard() {
        let trin = Trin::parse_from([
            "test",
            "create-dashboard",
            "http://localhost:8787",
            "username",
            "password",
            "http://docker:9090",
        ]);
        assert_eq!(
            trin,
            Trin::CreateDashboard(DashboardConfig {
                grafana_address: "http://localhost:8787".to_string(),
                grafana_username: "username".to_string(),
                grafana_password: "password".to_string(),
                prometheus_address: "http://docker:9090".to_string(),
            })
        );
    }
}
