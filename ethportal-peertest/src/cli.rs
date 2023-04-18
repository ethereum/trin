use clap::{Parser, ValueEnum};
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
        long = "target-transport",
        help = "Transport type of the node under test"
    )]
    pub target_transport: PeertestTransport,

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

#[derive(ValueEnum, Debug, PartialEq, Eq, Clone)]
pub enum PeertestTransport {
    Ipc,
    Http,
}

impl Default for PeertestConfig {
    fn default() -> Self {
        Self::parse_from([""])
    }
}

#[cfg(test)]
mod test {
    use crate::cli::PeertestConfig;
    use crate::cli::PeertestTransport;
    use clap::Parser;

    #[test]
    fn test_default_pasre_config() {
        let config = PeertestConfig::default();
        assert_eq!(config.listen_port, 9876);
        assert_eq!(config.target_transport, PeertestTransport::Ipc);
        assert_eq!(config.target_ipc_path, "/tmp/trin-jsonrpc.ipc");
        assert_eq!(config.target_http_address, "http://127.0.0.1:8545/");
    }

    #[test]
    fn test_parse_config_with_http() {
        let config = PeertestConfig::parse_from([
            "test",
            "--target-transport",
            "http",
            "--target-http-address",
            "http://127.0.0.1:5555/",
        ]);
        assert_eq!(config.listen_port, 9876);
        assert_eq!(config.target_transport, PeertestTransport::Http);
        assert_eq!(config.target_http_address, "http://127.0.0.1:5555/");
    }

    #[test]
    fn test_parse_config_with_ipc() {
        let config = PeertestConfig::parse_from([
            "test",
            "--target-transport",
            "ipc",
            "--target-ipc-path",
            "/tmp/test.ipc",
        ]);
        assert_eq!(config.listen_port, 9876);
        assert_eq!(config.target_transport, PeertestTransport::Ipc);
        assert_eq!(config.target_ipc_path, "/tmp/test.ipc");
    }

    #[test]
    fn test_parse_config_with_listen_port() {
        let config = PeertestConfig::parse_from(["test", "--listen-port", "5555"]);
        assert_eq!(config.listen_port, 5555);
        assert_eq!(config.target_transport, PeertestTransport::Ipc);
        assert_eq!(config.target_ipc_path, "/tmp/trin-jsonrpc.ipc");
    }
}
