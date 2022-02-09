use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use serde_json::value::RawValue;
use structopt::StructOpt;
// todo
use thiserror::Error;

use trin_core::cli::DEFAULT_WEB3_IPC_PATH;

#[derive(StructOpt, Debug)]
#[structopt(
    name = "trin-cli",
    version = "0.0.1",
    author = "Ethereum Foundation",
    about = "Run JSON-RPC commands against trin nodes"
)]
struct Config {
    #[structopt(
        default_value(DEFAULT_WEB3_IPC_PATH),
        long,
        help = "path to JSON-RPC endpoint"
    )]
    ipc: PathBuf,

    #[structopt(help = "e.g. discv5_routingTableInfo", required = true)]
    endpoint: String,

    #[structopt(long, help = "parameters", use_delimiter = true)]
    params: Option<Vec<String>>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Config {
        ipc,
        endpoint,
        params,
    } = Config::from_args();

    let params: Option<Vec<Box<RawValue>>> =
        params.map(|param| param.into_iter().map(jsonrpc::arg).collect());

    eprintln!(
        "Attempting RPC. endpoint={} params={:?} file={}",
        endpoint,
        params,
        ipc.to_string_lossy()
    );
    let mut client = TrinClient::from_ipc(&ipc)?;

    let req = client.build_request(endpoint.as_str(), &params);
    let resp = client.make_request(req)?;

    println!("{}", serde_json::to_string_pretty(&resp).unwrap());
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
