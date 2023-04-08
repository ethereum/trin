use clap::Parser;
use trin_types::cli::{
    DEFAULT_WEB3_HTTP_ADDRESS as DEFAULT_TARGET_HTTP_ADDRESS,
    DEFAULT_WEB3_IPC_PATH as DEFAULT_TARGET_IPC_PATH,
};

const DEFAULT_LISTEN_PORT: &str = "9876";

#[derive(Parser, Debug, PartialEq, Eq, Clone)]
#[command(
    name = "ethportal-peertest",
    version = "0.0.1",
    about = "Testing framework for portal network peer-to-peer network calls"
)]
pub struct PeertestConfig {
    #[arg(
        default_value = DEFAULT_LISTEN_PORT,
        short = 'p',
        long = "listen-port",
        help = "The UDP port to listen on."
    )]
    pub listen_port: u16,

    #[arg(
        default_value = "ipc",
        value_parser = ["http", "ipc"],
        long = "target-transport",
        help = "Transport type of the node under test"
    )]
    pub target_transport: String,

    #[arg(
        default_value = DEFAULT_TARGET_IPC_PATH,
        long = "target-ipc-path",
        help = "IPC path of target node under test"
    )]
    pub target_ipc_path: String,

    #[arg(
        default_value = DEFAULT_TARGET_HTTP_ADDRESS,
        long = "target-http-address",
        help = "HTTP address of target node under test"
    )]
    pub target_http_address: String,
}

impl Default for PeertestConfig {
    fn default() -> Self {
        Self::parse_from([""].iter())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        PeertestConfig::command().debug_assert()
    }
}
