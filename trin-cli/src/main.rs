use structopt::StructOpt;
use std::path::PathBuf;
use std::os::unix::net::UnixStream;

use trin_core::cli::DEFAULT_WEB3_IPC_PATH;

#[derive(StructOpt, Debug)]
#[structopt(
    name = "trin-cli",
    version = "0.0.1",
    author = "Ethereum Foundation",
    about = "Utilities for interacting with trin nodes",
)]
enum Config {
    #[structopt(
        about = "run JSON-RPC commands",
    )]
    RPC {
        #[structopt(
            default_value(DEFAULT_WEB3_IPC_PATH),
            long,
            help = "path to JSON-RPC endpoint",
        )]
        ipc: PathBuf,

        #[structopt(
            help = "e.g. discv5_routingTableInfo",
            required = true,
        )]
        endpoint: String,
    },

    #[structopt(
        about = "show list of available JSON-RPC methods",
    )]
    ListEndpoints,
}

/*
 * I have a large mapping from strings to structs describing each endpoint.
 * RPC attempts to trigger the endpoint
 * ListEndpoints operates directly on that map
 *
 * Alt: just pass the endpoint along and see if it works
 */

fn main() {
    let config = Config::from_args();

    match config {
        Config::RPC {ipc, endpoint} => {
            println!("RPC {:?} {}", ipc, endpoint);

            let mut client = TrinClient::from_ipc(&ipc).unwrap();
            let resp = client.routing_table_info();
            println!("resp: {:?}", resp);

            // TODO: serialize these in a prettier way
            let resp = client.state_data_radius();
            println!("resp: {:?}", resp);
        }
        Config::ListEndpoints => {
            println!("List Endpoints");
        }
    };
}

fn build_request<'a>(method: &'a str, request_id: u64) -> jsonrpc::Request<'a> {
    jsonrpc::Request {
        method: method,
        params: &[],
        id: serde_json::json!(request_id),
        jsonrpc: Some("2.0"),
    }
}

// TODO: these belong in trin_core::jsonrpc::types
#[derive(Debug, serde::Deserialize)]
pub struct RoutingTableNodeInfo {
    pub node_id: String,
    pub enr: String,
    pub status: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct RoutingTableInfoResponse {
    pub buckets: Vec<RoutingTableNodeInfo>,

    #[serde(rename="localKey")]
    pub local_node_id: String,
}

pub trait ParseResponse
{
    fn parse(value: jsonrpc::Response) -> Result<Self, &'static str> where Self: Sized;
}

// this looks exactly like TryFrom, but we cannot provide a blanket implementation of
// TryFrom for two reasons:
// - a conflicting blanket implementation already exists in core (TryInto)
// - we cannot write blanket implementations for traits which are not defined in our crate
// We use DeserializeOwned in lieu of Deserialize because this is called in a loop where
//  some data is read from a socket, then a response is returned, then the original data
//  is thrown away. In order for the lifetimes to work out our responses must not hold any
//  references to the original data. More on that here: https://serde.rs/lifetimes.html
impl<T> ParseResponse for T
where T: serde::de::DeserializeOwned {
    fn parse(value: jsonrpc::Response) -> Result<Self, &'static str> where Self: Sized{
        if let Some(ref raw_value) = value.result {
            Ok(serde_json::from_str(raw_value.get()).unwrap())
        } else {
            // TODO: handle the error case!
            Err("no value")
        }
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(transparent)]
pub struct DataRadiusResponse {
    pub data_radius: String,
}

pub trait TryClone {
    fn try_clone(&self) -> std::io::Result<Self> where Self: Sized;
}

impl TryClone for UnixStream {
    fn try_clone(&self) -> std::io::Result<Self> {
        UnixStream::try_clone(self)
    }
}

pub struct TrinClient<S>
where S: std::io::Read + std::io::Write + TryClone
{
    stream: S,
    request_id: u64,
}

impl TrinClient<UnixStream>
{
    fn from_ipc(path: &PathBuf) -> std::io::Result<Self> {
        // TODO: a nice error if this file does not exist
        Ok(Self {
            stream: UnixStream::connect(path)?,
            request_id: 0
        })
    }
}

// TryClone is used because JSON-RPC responses are not followed by EOF. We must read bytes
// from the stream until a complete object is detected, and the simplest way of doing that
// with available APIs is to give ownership of a Read to a serde_json::Deserializer. If we
// gave it exclusive ownership that would require us to open a new connection for every
// command we wanted to send! By making a clone (or, by trying to) we can have our cake
// and eat it too.
impl<'a, S> TrinClient<S>
where S: std::io::Read + std::io::Write + TryClone
{
    fn build_request(&mut self, method: &'a str) -> jsonrpc::Request<'a> {
        let result = build_request(method, self.request_id);
        self.request_id += 1;
        
        result
    }

    // TODO: a lot of error handling cleanup
    fn make_request<T: serde::de::DeserializeOwned>(&mut self, req: jsonrpc::Request) -> T {
        let data = serde_json::to_vec(&req).unwrap();

        self.stream.write_all(&data).unwrap();
        self.stream.flush().unwrap();

        let clone = self.stream.try_clone().unwrap();
        let deser = serde_json::Deserializer::from_reader(clone);
        for obj in deser.into_iter::<jsonrpc::Response>() {
            let response_obj = obj.unwrap();
            println!("response: {:?}", response_obj);
            let resp = T::parse(response_obj);
            return resp.unwrap();
        }

        // TODO: is this actually unreachable? What if they immediately send EOF?
        unreachable!()
    }

    fn routing_table_info(&mut self) -> RoutingTableInfoResponse {
        let req = self.build_request("discv5_routingTableInfo");
        self.make_request(req)
    }

    fn state_data_radius(&mut self) -> DataRadiusResponse {
        let req = self.build_request("portalState_dataRadius");
        self.make_request(req)
    }
}
