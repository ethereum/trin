use std::env;
use std::ffi::OsString;
use structopt::StructOpt;
use trin_core::cli::DEFAULT_WEB3_HTTP_ADDRESS as DEFAULT_TARGET_HTTP_ADDRESS;
use trin_core::cli::DEFAULT_WEB3_IPC_PATH as DEFAULT_TARGET_IPC_PATH;

const DEFAULT_LISTEN_PORT: &str = "9876";
const DEFAULT_WEB3_IPC_PATH: &str = "/tmp/json-rpc-peertest.ipc";

#[derive(StructOpt, Debug, PartialEq, Clone)]
#[structopt(
    name = "ethportal-peertest",
    version = "0.0.1",
    about = "Testing framework for portal network peer-to-peer network calls"
)]
pub struct PeertestConfig {
    #[structopt(
        default_value(DEFAULT_LISTEN_PORT),
        short = "p",
        long = "listen-port",
        help = "The UDP port to listen on."
    )]
    pub listen_port: u16,

    #[structopt(
        default_value(DEFAULT_WEB3_IPC_PATH),
        long = "web3-ipc-path",
        help = "path to json-rpc socket address over IPC"
    )]
    pub web3_ipc_path: String,

    #[structopt(
        short,
        long = "target-node",
        help = "Base64-encoded ENR of the node under test"
    )]
    pub target_node: String,

    #[structopt(
        default_value = "ipc",
        possible_values(&["http", "ipc"]),
        long = "target-transport",
        help = "Transport type of the node under test"
    )]
    pub target_transport: String,

    #[structopt(
        default_value = DEFAULT_TARGET_IPC_PATH,
        long = "target-ipc-path",
        help = "IPC path of target node under test"
    )]
    pub target_ipc_path: String,

    #[structopt(
        default_value = DEFAULT_TARGET_HTTP_ADDRESS,
        long = "target-http-address",
        help = "HTTP address of target node under test"
    )]
    pub target_http_address: String,
}

impl PeertestConfig {
    pub fn from_cli() -> Self {
        Self::new_from(env::args_os()).expect("Could not parse ethportal-peertest arguments")
    }

    pub fn new_from<I, T>(args: I) -> Result<Self, String>
    where
        I: Iterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let config = Self::from_iter(args);

        Ok(config)
    }
}

impl Default for PeertestConfig {
    fn default() -> Self {
        Self::new_from(["."].iter()).unwrap()
    }
}
