use std::{env, ffi::OsString, fmt, net::SocketAddr, path::PathBuf};

use structopt::StructOpt;

use crate::portalnet::types::messages::HexData;
use crate::utils::provider::TrustedProviderType;

pub const DEFAULT_MASTER_ACC_PATH: &str = "src/assets/merge_macc.bin";
pub const DEFAULT_WEB3_IPC_PATH: &str = "/tmp/trin-jsonrpc.ipc";
pub const DEFAULT_WEB3_HTTP_ADDRESS: &str = "127.0.0.1:8545";
const DEFAULT_DISCOVERY_PORT: &str = "9000";
pub const HISTORY_NETWORK: &str = "history";
pub const STATE_NETWORK: &str = "state";
const DEFAULT_SUBNETWORKS: &str = "history";
pub const DEFAULT_STORAGE_CAPACITY: &str = "100000"; // 100mb
pub const DEFAULT_TRUSTED_PROVIDER: &str = "infura";

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
        default_value = "5",
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
        long = "enable-metrics-with-url",
        help = "Enable prometheus metrics reporting (provide local IP/Port from which your Prometheus server is configured to fetch metrics)"
    )]
    pub enable_metrics_with_url: Option<SocketAddr>,

    #[structopt(
        short = "e",
        long = "ephemeral",
        help = "Use temporary data storage that is deleted on exit."
    )]
    pub ephemeral: bool,

    #[structopt(
        long = "trusted-provider",
        help = "Trusted provider to use. (options: 'infura' (default) or 'geth' (experimental))",
        default_value(DEFAULT_TRUSTED_PROVIDER)
    )]
    pub trusted_provider: TrustedProviderType,

    #[structopt(
        long = "geth-url",
        help = "URL for geth client to use as trusted http provider (experimental)"
    )]
    pub geth_url: Option<String>,

    // todo: support custom master accs
    #[structopt(
        long = "master-accumulator-path",
        help = "Path to master accumulator for validation (not currently supported)",
        default_value(DEFAULT_MASTER_ACC_PATH),
        parse(from_os_str)
    )]
    pub master_acc_path: PathBuf,
}

impl Default for TrinConfig {
    fn default() -> Self {
        TrinConfig {
            web3_transport: "ipc".to_string(),
            web3_http_address: DEFAULT_WEB3_HTTP_ADDRESS.to_string(),
            web3_ipc_path: DEFAULT_WEB3_IPC_PATH.to_string(),
            pool_size: 5,
            discovery_port: DEFAULT_DISCOVERY_PORT.parse().unwrap(),
            bootnodes: vec![],
            external_addr: None,
            no_stun: false,
            private_key: None,
            networks: DEFAULT_SUBNETWORKS
                .split(',')
                .map(|n| n.to_string())
                .collect(),
            kb: DEFAULT_STORAGE_CAPACITY.parse().unwrap(),
            enable_metrics_with_url: None,
            ephemeral: false,
            trusted_provider: TrustedProviderType::Infura,
            geth_url: None,
            master_acc_path: PathBuf::from(DEFAULT_MASTER_ACC_PATH.to_string()),
        }
    }
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

        if config.master_acc_path != PathBuf::from(DEFAULT_MASTER_ACC_PATH.to_string()) {
            panic!("Custom master accumulators are not yet supported.")
        }

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

        match config.geth_url {
            Some(_) => {
                if config.trusted_provider != TrustedProviderType::Geth {
                    panic!("--geth-url flag is incompatible without Geth as the trusted provider.")
                }
            }
            None => {
                if config.trusted_provider == TrustedProviderType::Geth {
                    panic!("Using Geth for a trusted provider requires a --geth-url flag.")
                }
            }
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

impl fmt::Display for TrinConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let json_rpc_url = match self.web3_transport.as_str() {
            "http" => &self.web3_http_address,
            "ipc" => &self.web3_ipc_path,
            _ => "",
        };

        write!(
            f,
            "TrinConfig {{ networks: {:?}, capacity_kb: {}, ephemeral: {}, json_rpc_url: {}, pool_size: {}, metrics_enabled: {} }}",
            self.networks, self.kb, self.ephemeral, json_rpc_url, self.pool_size, self.enable_metrics_with_url.is_some()
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::env;
    use std::net::{IpAddr, Ipv4Addr};
    use test_log::test;

    fn env_is_set() -> bool {
        matches!(env::var("TRIN_INFURA_PROJECT_ID"), Ok(_))
    }

    #[test]
    fn test_default_args() {
        assert!(env_is_set());
        let expected_config = TrinConfig::default();
        let actual_config = TrinConfig::new_from(["trin"].iter()).unwrap();
        assert_eq!(actual_config.web3_transport, expected_config.web3_transport);
        assert_eq!(
            actual_config.web3_http_address,
            expected_config.web3_http_address
        );
        assert_eq!(actual_config.pool_size, expected_config.pool_size);
        assert_eq!(actual_config.external_addr, expected_config.external_addr);
        assert_eq!(actual_config.no_stun, expected_config.no_stun);
        assert_eq!(actual_config.ephemeral, expected_config.ephemeral);
    }

    #[test]
    fn test_custom_http_args() {
        assert!(env_is_set());
        let expected_config = TrinConfig {
            web3_http_address: "0.0.0.0:8080".to_string(),
            pool_size: 3,
            web3_transport: "http".to_string(),
            ..Default::default()
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
            web3_http_address: DEFAULT_WEB3_HTTP_ADDRESS.to_string(),
            web3_transport: "ipc".to_string(),
            ..Default::default()
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
            web3_http_address: DEFAULT_WEB3_HTTP_ADDRESS.to_string(),
            web3_ipc_path: "/path/test.ipc".to_string(),
            web3_transport: "ipc".to_string(),
            ..Default::default()
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
            discovery_port: 999,
            ..Default::default()
        };
        let actual_config =
            TrinConfig::new_from(["trin", "--discovery-port", "999"].iter()).unwrap();
        assert_eq!(actual_config.discovery_port, expected_config.discovery_port);
    }

    #[test]
    fn test_custom_bootnodes() {
        assert!(env_is_set());
        let expected_config = TrinConfig {
            bootnodes: vec!["enr:-aoeu".to_string(), "enr:-htns".to_string()],
            ..Default::default()
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
            private_key: Some(HexData(vec![1; 32])),
            ..Default::default()
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
    fn test_ephemeral() {
        assert!(env_is_set());
        let expected_config = TrinConfig {
            ephemeral: true,
            ..Default::default()
        };
        let actual_config = TrinConfig::new_from(["trin", "--ephemeral"].iter()).unwrap();
        assert_eq!(actual_config.ephemeral, expected_config.ephemeral);
    }

    #[test]
    fn test_enable_metrics_with_url() {
        assert!(env_is_set());
        let expected_config = TrinConfig {
            enable_metrics_with_url: Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                1234,
            )),
            ..Default::default()
        };
        let actual_config =
            TrinConfig::new_from(["trin", "--enable-metrics-with-url", "127.0.0.1:1234"].iter())
                .unwrap();
        assert_eq!(
            actual_config.enable_metrics_with_url,
            expected_config.enable_metrics_with_url
        );
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

    #[test]
    fn test_default_trusted_provider_is_infura() {
        assert!(env_is_set());
        let config = TrinConfig::new_from(["trin"].iter()).unwrap();
        assert_eq!(config.trusted_provider, TrustedProviderType::Infura);
    }

    #[test]
    fn test_geth_trusted_provider() {
        assert!(env_is_set());
        let config = TrinConfig::new_from(
            [
                "trin",
                "--trusted-provider",
                "geth",
                "--geth-url",
                "www.geth.com",
            ]
            .iter(),
        )
        .unwrap();
        assert_eq!(config.trusted_provider, TrustedProviderType::Geth);
    }

    #[test]
    #[should_panic(expected = "requires a --geth-url flag")]
    fn test_geth_trusted_provider_requires_geth_url() {
        assert!(env_is_set());
        TrinConfig::new_from(["trin", "--trusted-provider", "geth"].iter()).unwrap();
    }

    #[test]
    #[should_panic(expected = "Invalid trusted provider arg")]
    fn test_trusted_provider_invalid_argument() {
        assert!(env_is_set());
        TrinConfig::new_from(["trin", "--trusted-provider", "prysm"].iter()).unwrap();
    }

    #[test]
    #[should_panic(expected = "incompatible without Geth as the trusted provider")]
    fn test_geth_url_invalid_without_geth_as_trusted_provider() {
        assert!(env_is_set());
        TrinConfig::new_from(["trin", "--geth-url", "www.geth.com"].iter()).unwrap();
    }

    #[test]
    #[should_panic(expected = "incompatible without Geth as the trusted provider")]
    fn test_geth_url_invalid_with_infura_as_trusted_provider() {
        assert!(env_is_set());
        TrinConfig::new_from(
            [
                "trin",
                "--trusted-provider",
                "infura",
                "--geth-url",
                "www.geth.com",
            ]
            .iter(),
        )
        .unwrap();
    }
}
