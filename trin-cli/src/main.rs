pub mod dashboard;
use clap::{Args, Parser, Subcommand};

#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(windows)]
use uds_windows::UnixStream;

use std::path::{Path, PathBuf};

use ethereum_types::H256;
use serde_json::value::RawValue;
use thiserror::Error;

use dashboard::grafana::{GrafanaAPI, DASHBOARD_TEMPLATES};
use ethportal_api::{BlockBodyKey, BlockHeaderKey, BlockReceiptsKey, HistoryContentKey};
use trin_types::cli::DEFAULT_WEB3_IPC_PATH;
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
    /// IPC path of target JSON-RPC endpoint.
    #[arg(default_value = DEFAULT_WEB3_IPC_PATH, long)]
    ipc: PathBuf,

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Trin::parse() {
        Trin::JsonRpc(rpc) => json_rpc(rpc),
        Trin::EncodeKey(content_key) => encode_content_key(content_key),
        Trin::CreateDashboard(dashboard_config) => create_dashboard(dashboard_config),
    }
}

fn json_rpc(rpc: JsonRpc) -> Result<(), Box<dyn std::error::Error>> {
    let params: Option<Vec<Box<RawValue>>> = rpc
        .params
        .map(|param| param.into_iter().map(jsonrpc::arg).collect());
    eprintln!(
        "Attempting RPC. endpoint={} params={:?} file={}",
        rpc.endpoint,
        params,
        rpc.ipc.to_string_lossy()
    );
    let mut client = TrinClient::from_ipc(&rpc.ipc)?;

    let req = client.build_request(rpc.endpoint.as_str(), &params);
    let resp = client.make_request(req)?;

    println!("{}", serde_json::to_string_pretty(&resp).unwrap());

    Ok(())
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

fn build_request<'a>(
    method: &'a str,
    raw_params: &'a Option<Vec<Box<RawValue>>>,
    request_id: u64,
) -> jsonrpc::Request<'a> {
    match raw_params {
        Some(val) => jsonrpc::Request {
            method,
            params: val,
            id: serde_json::json!(request_id),
            jsonrpc: Some("2.0"),
        },
        None => jsonrpc::Request {
            method,
            params: &[],
            id: serde_json::json!(request_id),
            jsonrpc: Some("2.0"),
        },
    }
}

pub trait TryClone {
    fn try_clone(&self) -> std::io::Result<Self>
    where
        Self: Sized;
}

impl TryClone for UnixStream {
    fn try_clone(&self) -> std::io::Result<Self> {
        UnixStream::try_clone(self)
    }
}

pub struct TrinClient<S>
where
    S: std::io::Read + std::io::Write + TryClone,
{
    stream: S,
    request_id: u64,
}

impl TrinClient<UnixStream> {
    fn from_ipc(path: &Path) -> std::io::Result<Self> {
        // TODO: a nice error if this file does not exist
        Ok(Self {
            stream: UnixStream::connect(path)?,
            request_id: 0,
        })
    }
}

#[derive(Error, Debug)]
pub enum JsonRpcError {
    #[error("Received malformed response: {0}")]
    Malformed(serde_json::Error),

    #[error("Received empty response")]
    Empty,
}

// TryClone is used because JSON-RPC responses are not followed by EOF. We must read bytes
// from the stream until a complete object is detected, and the simplest way of doing that
// with available APIs is to give ownership of a Read to a serde_json::Deserializer. If we
// gave it exclusive ownership that would require us to open a new connection for every
// command we wanted to send! By making a clone (or, by trying to) we can have our cake
// and eat it too.
//
// TryClone is not necessary if TrinClient stays in this file forever; this script only
// needs to make a single request before it exits. However, in a future where TrinClient
// becomes the mechanism other parts of the codebase (such as peertester) use to act as
// JSON-RPC clients then this becomes necessary. So, this is slightly over-engineered but
// with an eye to future growth.
impl<'a, S> TrinClient<S>
where
    S: std::io::Read + std::io::Write + TryClone,
{
    fn build_request(
        &mut self,
        method: &'a str,
        params: &'a Option<Vec<Box<RawValue>>>,
    ) -> jsonrpc::Request<'a> {
        let result = build_request(method, params, self.request_id);
        self.request_id += 1;

        result
    }

    fn make_request(&mut self, req: jsonrpc::Request) -> Result<serde_json::Value, JsonRpcError> {
        let data = serde_json::to_vec(&req).unwrap();

        self.stream.write_all(&data).unwrap();
        self.stream.flush().unwrap();

        let clone = self.stream.try_clone().unwrap();
        let deser = serde_json::Deserializer::from_reader(clone);

        if let Some(obj) = deser.into_iter::<serde_json::Value>().next() {
            return obj.map_err(JsonRpcError::Malformed);
        }

        // this should only happen when they immediately send EOF
        Err(JsonRpcError::Empty)
    }
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
            "--ipc",
            "/tmp/trin.ipc",
            "--params",
            "p1,p2",
            "discv5_routingTableInfo",
        ]);
        assert_eq!(
            trin,
            Trin::JsonRpc(JsonRpc {
                ipc: PathBuf::from("/tmp/trin.ipc"),
                endpoint: "discv5_routingTableInfo".to_string(),
                params: Some(vec!["p1".to_string(), "p2".to_string()]),
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
