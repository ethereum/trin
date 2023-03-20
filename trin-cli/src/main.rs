pub mod dashboard;

#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(windows)]
use uds_windows::UnixStream;

use std::path::{Path, PathBuf};

use ethereum_types::H256;
use serde_json::value::RawValue;
use structopt::StructOpt;
use thiserror::Error;

use dashboard::grafana::GrafanaAPI;
use trin_core::portalnet::types::content_key::{
    BlockBody, BlockHeader, BlockReceipts, HistoryContentKey,
};
use trin_types::cli::DEFAULT_WEB3_IPC_PATH;
use trin_utils::bytes::hex_encode;

#[derive(StructOpt)]
#[structopt(
    name = "trin-cli",
    version = "0.0.1",
    author = "Ethereum Foundation",
    about = "Portal Network command line utilities"
)]
enum Trin {
    JsonRpc(JsonRpc),
    EncodeKey(EncodeKey),
    CreateDashboard(DashboardConfig),
}

/// Run JSON-RPC commands against a trin node.
#[derive(StructOpt, Debug)]
struct JsonRpc {
    /// IPC path of target JSON-RPC endpoint.
    #[structopt(default_value(DEFAULT_WEB3_IPC_PATH), long)]
    ipc: PathBuf,

    /// JSON-RPC method (e.g. discv5_routingTableInfo).
    #[structopt(required = true)]
    endpoint: String,

    /// Comma-separated list of JSON-RPC parameters.
    #[structopt(long, use_delimiter = true)]
    params: Option<Vec<String>>,
}

// TODO: Remove clippy allow once a variant with non-"Block" prefix is added.
/// Encode a content key.
#[derive(StructOpt)]
#[allow(clippy::enum_variant_names)]
enum EncodeKey {
    /// Encode the content key for a block header.
    BlockHeader {
        /// Hex-encoded block hash (omit '0x' prefix).
        #[structopt(long)]
        block_hash: H256,
    },
    /// Encode the content key for a block body.
    BlockBody {
        /// Hex-encoded block hash (omit '0x' prefix).
        #[structopt(long)]
        block_hash: H256,
    },
    /// Encode the content key for a block's transaction receipts.
    BlockReceipts {
        /// Hex-encoded block hash (omit '0x' prefix).
        #[structopt(long)]
        block_hash: H256,
    },
}

#[derive(StructOpt)]
#[allow(clippy::enum_variant_names)]
struct DashboardConfig {
    #[structopt(default_value = "http://localhost:3000")]
    grafana_address: String,

    #[structopt(default_value = "admin")]
    grafana_username: String,

    #[structopt(default_value = "admin")]
    grafana_password: String,

    #[structopt(default_value = "http://host.docker.internal:8545")]
    trin_rpc_address: String,

    #[structopt(default_value = "http://host.docker.internal:9090")]
    prometheus_address: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Trin::from_args() {
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
            HistoryContentKey::BlockHeaderWithProof(BlockHeader {
                block_hash: block_hash.into(),
            })
        }
        EncodeKey::BlockBody { block_hash } => HistoryContentKey::BlockBody(BlockBody {
            block_hash: block_hash.into(),
        }),
        EncodeKey::BlockReceipts { block_hash } => {
            HistoryContentKey::BlockReceipts(BlockReceipts {
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

    // Create JSON-HTTP Datasource
    let json_rpc_uid = grafana.create_datasource(
        "yesoreyeram-infinity-datasource".to_string(),
        "json-rpc".to_string(),
        dashboard_config.trin_rpc_address,
    )?;

    let prometheus_uid = grafana.create_datasource(
        "prometheus".to_string(),
        "prometheus".to_string(),
        dashboard_config.prometheus_address,
    )?;

    let dashboard_url = grafana.create_dashboard(json_rpc_uid, prometheus_uid)?;

    println!("Dashboard successfully created: {dashboard_url}");
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
