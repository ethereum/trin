use crate::portalnet::types::HexData;

use std::env;
use std::ffi::OsString;
use std::net::SocketAddr;
use structopt::StructOpt;

const DEFAULT_WEB3_IPC_PATH: &str = "/tmp/trin-jsonrpc.ipc";
const DEFAULT_WEB3_HTTP_PORT: &str = "8545";
const DEFAULT_DISCOVERY_PORT: &str = "9000";

#[derive(StructOpt, Debug, PartialEq)]
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
    help = "select transport protocol to serve json-rpc endpoint")]
    pub web3_transport: String,

    #[structopt(
        default_value(DEFAULT_WEB3_HTTP_PORT),
        long = "web3-http-port",
        help = "port to accept json-rpc http connections"
    )]
    pub web3_http_port: u16,

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
        help = "The public IP address and port under which this node is accessible"
    )]
    pub external_addr: Option<SocketAddr>,

    #[structopt(
        validator(check_private_key_length),
        long = "unsafe-private-key",
        help = "Hex encoded 32 byte private key (considered unsafe to pass in pk as cli arg, as it's stored in terminal history - keyfile support coming soon)"
    )]
    pub private_key: Option<HexData>,
}

impl Default for TrinConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl TrinConfig {
    pub fn new() -> Self {
        Self::new_from(env::args_os()).expect("Could not parse trin arguments")
    }
    pub fn new_from<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: Iterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let config = Self::from_iter(args);

        println!("Launching trin...");

        match config.web3_transport.as_str() {
            "http" => match &config.web3_ipc_path[..] {
                DEFAULT_WEB3_IPC_PATH => {
                    println!(
                        "Protocol: {}\nWEB3 HTTP port: {}",
                        config.web3_transport, config.web3_http_port
                    )
                }
                _ => panic!("Must not supply an ipc path when using http protocol for json-rpc"),
            },
            "ipc" => match &config.web3_http_port.to_string()[..] {
                DEFAULT_WEB3_HTTP_PORT => {
                    println!(
                        "Protocol: {}\nIPC path: {}",
                        config.web3_transport, config.web3_ipc_path
                    )
                }
                _ => panic!("Must not supply an http port when using ipc protocol for json-rpc"),
            },
            val => panic!("Unsupported json-rpc protocol: {}", val),
        }

        println!("Pool Size: {}", config.pool_size);

        match config.bootnodes.is_empty() {
            true => println!("Bootnodes: None"),
            _ => println!("Bootnodes: {:?}", config.bootnodes),
        }
        Ok(config)
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

    fn env_is_set() -> bool {
        match env::var("TRIN_INFURA_PROJECT_ID") {
            Ok(_) => true,
            _ => false,
        }
    }

    #[test]
    fn test_default_args() {
        assert!(env_is_set());
        let expected_config = TrinConfig {
            web3_http_port: DEFAULT_WEB3_HTTP_PORT.parse::<u16>().unwrap(),
            web3_ipc_path: DEFAULT_WEB3_IPC_PATH.to_string(),
            pool_size: 2,
            web3_transport: "ipc".to_string(),
            discovery_port: DEFAULT_DISCOVERY_PORT.parse().unwrap(),
            bootnodes: vec![],
            external_addr: None,
            private_key: None,
        };
        let actual_config = TrinConfig::new_from(["trin"].iter()).unwrap();
        assert_eq!(actual_config.web3_transport, expected_config.web3_transport);
        assert_eq!(actual_config.web3_http_port, expected_config.web3_http_port);
        assert_eq!(actual_config.pool_size, expected_config.pool_size);
        assert_eq!(actual_config.external_addr, expected_config.external_addr);
    }

    #[test]
    fn test_custom_http_args() {
        assert!(env_is_set());
        let expected_config = TrinConfig {
            external_addr: None,
            private_key: None,
            web3_http_port: 8080,
            web3_ipc_path: DEFAULT_WEB3_IPC_PATH.to_string(),
            pool_size: 3,
            web3_transport: "http".to_string(),
            discovery_port: DEFAULT_DISCOVERY_PORT.parse().unwrap(),
            bootnodes: vec![],
        };
        let actual_config = TrinConfig::new_from(
            [
                "trin",
                "--web3-transport",
                "http",
                "--web3-http-port",
                "8080",
                "--pool-size",
                "3",
            ]
            .iter(),
        )
        .unwrap();
        assert_eq!(actual_config.web3_transport, expected_config.web3_transport);
        assert_eq!(actual_config.web3_http_port, expected_config.web3_http_port);
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
            web3_http_port: DEFAULT_WEB3_HTTP_PORT.parse::<u16>().unwrap(),
            web3_ipc_path: DEFAULT_WEB3_IPC_PATH.to_string(),
            pool_size: 2,
            web3_transport: "ipc".to_string(),
            discovery_port: DEFAULT_DISCOVERY_PORT.parse().unwrap(),
            bootnodes: vec![],
        };
        assert_eq!(actual_config.web3_transport, expected_config.web3_transport);
        assert_eq!(actual_config.web3_http_port, expected_config.web3_http_port);
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
            web3_http_port: DEFAULT_WEB3_HTTP_PORT.parse::<u16>().unwrap(),
            web3_ipc_path: "/path/test.ipc".to_string(),
            pool_size: 2,
            web3_transport: "ipc".to_string(),
            discovery_port: DEFAULT_DISCOVERY_PORT.parse().unwrap(),
            bootnodes: vec![],
        };
        assert_eq!(actual_config.web3_transport, expected_config.web3_transport);
        assert_eq!(actual_config.web3_http_port, expected_config.web3_http_port);
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
    #[should_panic(expected = "Must not supply an http port when using ipc")]
    fn test_ipc_protocol_rejects_custom_web3_http_port() {
        assert!(env_is_set());
        TrinConfig::new_from(
            [
                "trin",
                "--web3-transport",
                "ipc",
                "--web3-http-port",
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
            web3_http_port: DEFAULT_WEB3_HTTP_PORT.parse::<u16>().unwrap(),
            web3_ipc_path: DEFAULT_WEB3_IPC_PATH.to_string(),
            pool_size: 2,
            web3_transport: "ipc".to_string(),
            discovery_port: 999,
            bootnodes: vec![],
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
            web3_http_port: DEFAULT_WEB3_HTTP_PORT.parse::<u16>().unwrap(),
            web3_ipc_path: DEFAULT_WEB3_IPC_PATH.to_string(),
            pool_size: 2,
            web3_transport: "ipc".to_string(),
            discovery_port: DEFAULT_DISCOVERY_PORT.parse().unwrap(),
            bootnodes: vec!["enr:-aoeu".to_string(), "enr:-htns".to_string()],
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
            web3_http_port: DEFAULT_WEB3_HTTP_PORT.parse::<u16>().unwrap(),
            web3_ipc_path: DEFAULT_WEB3_IPC_PATH.to_string(),
            pool_size: 2,
            web3_transport: "ipc".to_string(),
            discovery_port: DEFAULT_DISCOVERY_PORT.parse().unwrap(),
            bootnodes: vec![],
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
