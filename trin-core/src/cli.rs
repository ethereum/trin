use std::{env, ffi::OsString, net::SocketAddr};

use log::info;
use structopt::StructOpt;

use crate::portalnet::types::messages::HexData;

pub const DEFAULT_WEB3_IPC_PATH: &str = "/tmp/trin-jsonrpc.ipc";
pub const DEFAULT_WEB3_HTTP_ADDRESS: &str = "127.0.0.1:8545";
const DEFAULT_DISCOVERY_PORT: &str = "9000";
pub const HISTORY_NETWORK: &str = "history";
pub const STATE_NETWORK: &str = "state";
const DEFAULT_SUBNETWORKS: &str = "history";
pub const DEFAULT_STORAGE_CAPACITY: &str = "100000"; // 100mb

#[derive(StructOpt, Debug, PartialEq, Clone)]
#[structopt(
    name = "trin",
    version = "0.0.1",
    author = "carver",
    about = "Run an eth portal client"
)]
pub struct TrinConfig {
    #[structopt(
        default_value = "ipc",
        possible_values(&["http", "ipc"]),
        long = "web3-transport",
        help = "select transport protocol to serve json-rpc endpoint"
    )]
    pub web3_transport: String,

    #[structopt(
        default_value(DEFAULT_WEB3_HTTP_ADDRESS),
        long = "web3-http-address",
        help = "address to accept json-rpc http connections"
    )]
    pub web3_http_address: String,

    #[structopt(
        default_value(DEFAULT_WEB3_IPC_PATH),
        long = "web3-ipc-path",
        help = "path to json-rpc endpoint over IPC"
    )]
    pub web3_ipc_path: String, // TODO: Change to PathBuf

    #[structopt(
        default_value = "2",
        long = "pool-size",
        help = "max size of threadpool"
    )]
    pub pool_size: u32,

    #[structopt(
        default_value(DEFAULT_DISCOVERY_PORT),
        long = "discovery-port",
        help = "The UDP port to listen on."
    )]
    pub discovery_port: u16,

    #[structopt(
        use_delimiter = true,
        long = "bootnodes",
        help = "One or more comma-delimited base64-encoded ENR's or multiaddr strings of peers to initially add to the local routing table"
    )]
    pub bootnodes: Vec<String>,

    #[structopt(
        long = "external-address",
        group = "external-ips",
        help = "(Only use this if you are behind a NAT) The address which will be advertised to peers (in an ENR). Changing it does not change which port or address trin binds to. Port number is required, ex: 127.0.0.1:9001"
    )]
    pub external_addr: Option<SocketAddr>,

    #[structopt(
        long = "no-stun",
        group = "external-ips",
        help = "Do not use STUN to determine an external IP. Leaves ENR entry for IP blank. Some users report better connections over VPN."
    )]
    pub no_stun: bool,

    #[structopt(
        validator(check_private_key_length),
        long = "unsafe-private-key",
        help = "Hex encoded 32 byte private key (considered unsafe as it's stored in terminal history - keyfile support coming soon)"
    )]
    pub private_key: Option<HexData>,

    #[structopt(
        long = "networks",
        help = "Comma-separated list of which portal subnetworks to activate",
        default_value = DEFAULT_SUBNETWORKS,
        use_delimiter = true
    )]
    pub networks: Vec<String>,

    /// Number of Kilobytes to store in the DB
    #[structopt(
        default_value(DEFAULT_STORAGE_CAPACITY),
        long,
        help = "Maximum number of kilobytes of total data to store in the DB"
    )]
    pub kb: u32,

    #[structopt(
        long = "enable-metrics",
        help = "Enable prometheus metrics reporting (requires --metrics-url)",
        requires = "metrics-url"
    )]
    pub enable_metrics: bool,

    #[structopt(long = "metrics-url", help = "URL for prometheus server")]
    pub metrics_url: Option<String>,
}

impl TrinConfig {
    pub fn from_cli() -> Self {
        Self::new_from(env::args_os()).expect("Could not parse trin arguments")
    }
    pub fn new_from<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: Iterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let config = Self::from_iter(args);

        match config.web3_transport.as_str() {
            "http" => match &config.web3_ipc_path[..] {
                DEFAULT_WEB3_IPC_PATH => {}
                _ => panic!("Must not supply an ipc path when using http protocol for json-rpc"),
            },
            "ipc" => match &config.web3_http_address[..] {
                DEFAULT_WEB3_HTTP_ADDRESS => {}
                _ => panic!("Must not supply an http address when using ipc protocol for json-rpc"),
            },
            val => panic!("Unsupported json-rpc protocol: {}", val),
        }

        Ok(config)
    }

    pub fn display_config(&self) {
        info!("Launching with config:");
        match self.web3_transport.as_str() {
            "http" => {
                info!("- JSON-RPC HTTP address: {}", self.web3_http_address)
            }
            "ipc" => {
                info!("- JSON-RPC IPC path: {}", self.web3_ipc_path)
            }
            val => panic!("Unsupported json-rpc transport: {}", val),
        }

        info!("- Pool Size: {}", self.pool_size);

        match self.bootnodes.is_empty() {
            true => info!("- Bootnodes: None"),
            _ => info!("- Bootnodes: {:?}", self.bootnodes),
        }
    }
}

fn check_private_key_length(private_key: String) -> Result<(), String> {
    if private_key.len() == 64 {
        return Ok(());
    }
    panic!(
        "Invalid private key length: {}, expected 32 byte hexstring",
        private_key
    )
}

#[cfg(test)]
mod test {
    use super::*;
    use std::env;
    use test_log::test;

    fn env_is_set() -> bool {
        matches!(env::var("TRIN_INFURA_PROJECT_ID"), Ok(_))
    }

    #[test]
    fn test_default_args() {
        assert!(env_is_set());
        let expected_config = TrinConfig {
            web3_http_address: DEFAULT_WEB3_HTTP_ADDRESS.to_string(),
            web3_ipc_path: DEFAULT_WEB3_IPC_PATH.to_string(),
            pool_size: 2,
            kb: DEFAULT_STORAGE_CAPACITY.parse().unwrap(),
            web3_transport: "ipc".to_string(),
            discovery_port: DEFAULT_DISCOVERY_PORT.parse().unwrap(),
            no_stun: false,
            bootnodes: vec![],
            external_addr: None,
            private_key: None,
            enable_metrics: false,
            metrics_url: None,
            networks: DEFAULT_SUBNETWORKS
                .split(',')
                .map(|n| n.to_string())
                .collect(),
        };
        let actual_config = TrinConfig::new_from(["trin"].iter()).unwrap();
        assert_eq!(actual_config.web3_transport, expected_config.web3_transport);
        assert_eq!(
            actual_config.web3_http_address,
            expected_config.web3_http_address
        );
        assert_eq!(actual_config.pool_size, expected_config.pool_size);
        assert_eq!(actual_config.external_addr, expected_config.external_addr);
    }

    #[test]
    fn test_custom_http_args() {
        assert!(env_is_set());
        let expected_config = TrinConfig {
            external_addr: None,
            private_key: None,
            kb: DEFAULT_STORAGE_CAPACITY.parse().unwrap(),
            web3_http_address: "0.0.0.0:8080".to_string(),
            web3_ipc_path: DEFAULT_WEB3_IPC_PATH.to_string(),
            pool_size: 3,
            web3_transport: "http".to_string(),
            discovery_port: DEFAULT_DISCOVERY_PORT.parse().unwrap(),
            no_stun: false,
            bootnodes: vec![],
            enable_metrics: false,
            metrics_url: None,
            networks: DEFAULT_SUBNETWORKS
                .split(',')
                .map(|n| n.to_string())
                .collect(),
        };
        let actual_config = TrinConfig::new_from(
            [
                "trin",
                "--web3-transport",
                "http",
                "--web3-http-address",
                "0.0.0.0:8080",
                "--pool-size",
                "3",
            ]
            .iter(),
        )
        .unwrap();
        assert_eq!(actual_config.web3_transport, expected_config.web3_transport);
        assert_eq!(
            actual_config.web3_http_address,
            expected_config.web3_http_address
        );
        assert_eq!(actual_config.pool_size, expected_config.pool_size);
    }

    #[test]
    fn test_ipc_protocol() {
        assert!(env_is_set());
        let actual_config =
            TrinConfig::new_from(["trin", "--web3-transport", "ipc"].iter()).unwrap();
        let expected_config = TrinConfig {
            external_addr: None,
            private_key: None,
            kb: DEFAULT_STORAGE_CAPACITY.parse().unwrap(),
            web3_http_address: DEFAULT_WEB3_HTTP_ADDRESS.to_string(),
            web3_ipc_path: DEFAULT_WEB3_IPC_PATH.to_string(),
            pool_size: 2,
            web3_transport: "ipc".to_string(),
            discovery_port: DEFAULT_DISCOVERY_PORT.parse().unwrap(),
            no_stun: false,
            bootnodes: vec![],
            enable_metrics: false,
            metrics_url: None,
            networks: DEFAULT_SUBNETWORKS
                .split(',')
                .map(|n| n.to_string())
                .collect(),
        };
        assert_eq!(actual_config.web3_transport, expected_config.web3_transport);
        assert_eq!(
            actual_config.web3_http_address,
            expected_config.web3_http_address
        );
        assert_eq!(actual_config.pool_size, expected_config.pool_size);
    }

    #[test]
    fn test_ipc_with_custom_path() {
        assert!(env_is_set());
        let actual_config = TrinConfig::new_from(
            [
                "trin",
                "--web3-transport",
                "ipc",
                "--web3-ipc-path",
                "/path/test.ipc",
            ]
            .iter(),
        )
        .unwrap();
        let expected_config = TrinConfig {
            private_key: None,
            external_addr: None,
            web3_http_address: DEFAULT_WEB3_HTTP_ADDRESS.to_string(),
            web3_ipc_path: "/path/test.ipc".to_string(),
            kb: DEFAULT_STORAGE_CAPACITY.parse().unwrap(),
            pool_size: 2,
            web3_transport: "ipc".to_string(),
            discovery_port: DEFAULT_DISCOVERY_PORT.parse().unwrap(),
            no_stun: false,
            bootnodes: vec![],
            enable_metrics: false,
            metrics_url: None,
            networks: DEFAULT_SUBNETWORKS
                .split(',')
                .map(|n| n.to_string())
                .collect(),
        };
        assert_eq!(actual_config.web3_transport, expected_config.web3_transport);
        assert_eq!(
            actual_config.web3_http_address,
            expected_config.web3_http_address
        );
        assert_eq!(actual_config.pool_size, expected_config.pool_size);
        assert_eq!(actual_config.web3_ipc_path, expected_config.web3_ipc_path);
    }

    #[test]
    #[should_panic(expected = "Must not supply an ipc path when using http")]
    fn test_http_protocol_rejects_custom_web3_ipc_path() {
        assert!(env_is_set());
        TrinConfig::new_from(
            [
                "trin",
                "--web3-transport",
                "http",
                "--web3-ipc-path",
                "/path/test.ipc",
            ]
            .iter(),
        )
        .unwrap_err();
    }

    #[test]
    #[should_panic(expected = "Must not supply an http address when using ipc")]
    fn test_ipc_protocol_rejects_custom_web3_http_address() {
        assert!(env_is_set());
        TrinConfig::new_from(
            [
                "trin",
                "--web3-transport",
                "ipc",
                "--web3-http-address",
                "7879",
            ]
            .iter(),
        )
        .unwrap_err();
    }

    #[test]
    fn test_custom_discovery_port() {
        assert!(env_is_set());
        let expected_config = TrinConfig {
            external_addr: None,
            private_key: None,
            web3_http_address: DEFAULT_WEB3_HTTP_ADDRESS.to_string(),
            web3_ipc_path: DEFAULT_WEB3_IPC_PATH.to_string(),
            pool_size: 2,
            kb: DEFAULT_STORAGE_CAPACITY.parse().unwrap(),
            web3_transport: "ipc".to_string(),
            discovery_port: 999,
            no_stun: false,
            bootnodes: vec![],
            enable_metrics: false,
            metrics_url: None,
            networks: DEFAULT_SUBNETWORKS
                .split(',')
                .map(|n| n.to_string())
                .collect(),
        };
        let actual_config =
            TrinConfig::new_from(["trin", "--discovery-port", "999"].iter()).unwrap();
        assert_eq!(actual_config.discovery_port, expected_config.discovery_port);
    }

    #[test]
    fn test_custom_bootnodes() {
        assert!(env_is_set());
        let expected_config = TrinConfig {
            external_addr: None,
            private_key: None,
            web3_http_address: DEFAULT_WEB3_HTTP_ADDRESS.to_string(),
            web3_ipc_path: DEFAULT_WEB3_IPC_PATH.to_string(),
            pool_size: 2,
            kb: DEFAULT_STORAGE_CAPACITY.parse().unwrap(),
            web3_transport: "ipc".to_string(),
            discovery_port: DEFAULT_DISCOVERY_PORT.parse().unwrap(),
            no_stun: false,
            bootnodes: vec!["enr:-aoeu".to_string(), "enr:-htns".to_string()],
            enable_metrics: false,
            metrics_url: None,
            networks: DEFAULT_SUBNETWORKS
                .split(',')
                .map(|n| n.to_string())
                .collect(),
        };
        let actual_config =
            TrinConfig::new_from(["trin", "--bootnodes", "enr:-aoeu,enr:-htns"].iter()).unwrap();
        assert_eq!(actual_config.bootnodes, expected_config.bootnodes);
    }

    #[test]
    fn test_manual_external_addr_v4() {
        assert!(env_is_set());
        let actual_config =
            TrinConfig::new_from(["trin", "--external-address", "127.0.0.1:1234"].iter()).unwrap();
        assert_eq!(
            actual_config.external_addr,
            Some(SocketAddr::from(([127, 0, 0, 1], 1234)))
        );
    }

    #[test]
    fn test_manual_external_addr_v6() {
        assert!(env_is_set());
        let actual_config =
            TrinConfig::new_from(["trin", "--external-address", "[::1]:1234"].iter()).unwrap();
        assert_eq!(
            actual_config.external_addr,
            Some(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 1234)))
        );
    }

    #[test]
    fn test_custom_private_key() {
        assert!(env_is_set());
        let expected_config = TrinConfig {
            external_addr: None,
            private_key: Some(HexData(vec![1; 32])),
            web3_http_address: DEFAULT_WEB3_HTTP_ADDRESS.to_string(),
            web3_ipc_path: DEFAULT_WEB3_IPC_PATH.to_string(),
            pool_size: 2,
            kb: DEFAULT_STORAGE_CAPACITY.parse().unwrap(),
            web3_transport: "ipc".to_string(),
            discovery_port: DEFAULT_DISCOVERY_PORT.parse().unwrap(),
            no_stun: false,
            bootnodes: vec![],
            enable_metrics: false,
            metrics_url: None,
            networks: DEFAULT_SUBNETWORKS
                .split(',')
                .map(|n| n.to_string())
                .collect(),
        };
        let actual_config = TrinConfig::new_from(
            [
                "trin",
                "--unsafe-private-key",
                "0101010101010101010101010101010101010101010101010101010101010101",
            ]
            .iter(),
        )
        .unwrap();
        assert_eq!(actual_config.private_key, expected_config.private_key);
    }

    #[test]
    #[should_panic(expected = "Invalid private key length")]
    fn test_custom_private_key_odd_length() {
        assert!(env_is_set());
        TrinConfig::new_from(
            [
                "trin",
                "--unsafe-private-key",
                "010101010101010101010101010101010101010101010101010101010101010",
            ]
            .iter(),
        )
        .unwrap_err();
    }

    #[test]
    #[should_panic(expected = "Invalid private key length")]
    fn test_custom_private_key_requires_32_bytes() {
        assert!(env_is_set());
        TrinConfig::new_from(
            [
                "trin",
                "--unsafe-private-key",
                "01010101010101010101010101010101010101010101010101010101010101",
            ]
            .iter(),
        )
        .unwrap_err();
    }
}
