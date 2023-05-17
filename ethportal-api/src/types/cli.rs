use std::{env, ffi::OsString, fmt, net::SocketAddr, path::PathBuf, str::FromStr};

use clap::{arg, Args, Parser, Subcommand};
use ethereum_types::H256;
use url::Url;

use crate::types::bootnodes::Bootnodes;
use crate::types::provider::TrustedProviderType;

pub const DEFAULT_MASTER_ACC_PATH: &str = "validation_assets/merge_macc.bin";
pub const DEFAULT_WEB3_IPC_PATH: &str = "/tmp/trin-jsonrpc.ipc";
pub const DEFAULT_WEB3_HTTP_ADDRESS: &str = "http://127.0.0.1:8545/";
pub const DEFAULT_WEB3_HTTP_PORT: u16 = 8545;
pub const DEFAULT_WEB3_WS_PORT: u16 = 8546;
const DEFAULT_DISCOVERY_PORT: &str = "9000";
pub const BEACON_NETWORK: &str = "beacon";
pub const HISTORY_NETWORK: &str = "history";
pub const STATE_NETWORK: &str = "state";
const DEFAULT_SUBNETWORKS: &str = "history";
pub const DEFAULT_STORAGE_CAPACITY_MB: &str = "100";
pub const DEFAULT_TRUSTED_PROVIDER: &str = "infura";
pub const DEFAULT_WEB3_TRANSPORT: &str = "ipc";

use crate::dashboard::grafana::{GrafanaAPI, DASHBOARD_TEMPLATES};

#[derive(Debug, PartialEq, Clone)]
pub enum Web3TransportType {
    HTTP,
    IPC,
}

impl fmt::Display for Web3TransportType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::HTTP => write!(f, "http"),
            Self::IPC => write!(f, "ipc"),
        }
    }
}

impl FromStr for Web3TransportType {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "http" => Ok(Web3TransportType::HTTP),
            "ipc" => Ok(Web3TransportType::IPC),
            _ => Err("Invalid web3-transport arg. Expected either 'http' or 'ipc'"),
        }
    }
}

#[derive(Parser, Debug, PartialEq, Clone)]
#[command(
    name = "trin",
    version = "0.0.1",
    author = "carver",
    about = "Run an eth portal client"
)]
pub struct TrinConfig {
    #[arg(
        default_value = DEFAULT_WEB3_TRANSPORT,
        long = "web3-transport",
        help = "select transport protocol to serve json-rpc endpoint"
    )]
    pub web3_transport: Web3TransportType,

    #[arg(
        default_value = DEFAULT_WEB3_HTTP_ADDRESS,
        long = "web3-http-address",
        help = "address to accept json-rpc http connections"
    )]
    pub web3_http_address: Url,

    #[arg(
        default_value = DEFAULT_WEB3_IPC_PATH,
        long = "web3-ipc-path",
        help = "path to json-rpc endpoint over IPC"
    )]
    pub web3_ipc_path: PathBuf,

    #[arg(
        default_value = DEFAULT_DISCOVERY_PORT,
        long = "discovery-port",
        help = "The UDP port to listen on."
    )]
    pub discovery_port: u16,

    #[arg(
        default_value = "default",
        long = "bootnodes",
        help = "One or more comma-delimited base64-encoded ENR's or multiaddr strings of peers to initially add to the local routing table"
    )]
    pub bootnodes: Bootnodes,

    #[arg(
        long = "external-address",
        group = "external-ips",
        help = "(Only use this if you are behind a NAT) The address which will be advertised to peers (in an ENR). Changing it does not change which port or address trin binds to. Port number is required, ex: 127.0.0.1:9001"
    )]
    pub external_addr: Option<SocketAddr>,

    #[arg(
        long = "no-stun",
        group = "external-ips",
        help = "Do not use STUN to determine an external IP. Leaves ENR entry for IP blank. Some users report better connections over VPN."
    )]
    pub no_stun: bool,

    #[arg(
        long = "unsafe-private-key",
        value_parser = check_private_key_length,
        help = "Hex encoded 32 byte private key (with 0x prefix) (considered unsafe as it's stored in terminal history - keyfile support coming soon)"
    )]
    pub private_key: Option<H256>,

    #[arg(
    long = "networks",
        help = "Comma-separated list of which portal subnetworks to activate",
        default_value = DEFAULT_SUBNETWORKS,
        use_value_delimiter = true
    )]
    pub networks: Vec<String>,

    /// Storage capacity specified in megabytes.
    #[arg(
        default_value(DEFAULT_STORAGE_CAPACITY_MB),
        long,
        help = "Maximum number of megabytes of total data to store in the DB (actual usage will exceed limit due to overhead)"
    )]
    pub mb: u32,

    #[arg(
        long = "enable-metrics-with-url",
        help = "Enable prometheus metrics reporting (provide local IP/Port from which your Prometheus server is configured to fetch metrics)"
    )]
    pub enable_metrics_with_url: Option<SocketAddr>,

    #[arg(
        short = 'e',
        long = "ephemeral",
        help = "Use temporary data storage that is deleted on exit."
    )]
    pub ephemeral: bool,

    #[arg(
        long = "trusted-provider",
        help = "Trusted provider to use. (options: 'infura' (default), 'pandaops' (devops) or 'custom')",
        default_value(DEFAULT_TRUSTED_PROVIDER)
    )]
    pub trusted_provider: TrustedProviderType,

    #[arg(
        long = "trusted-provider-url",
        value_parser = check_url_format,
        help = "URL for a trusted http provider. Must include a base, host and port (e.g., '<base>://<host>:<port>')."
    )]
    pub trusted_provider_url: Option<Url>,

    #[arg(
        long = "master-accumulator-path",
        help = "Path to master accumulator for validation",
        default_value(DEFAULT_MASTER_ACC_PATH)
    )]
    pub master_acc_path: PathBuf,

    #[command(subcommand)]
    pub command: Option<TrinConfigCommands>,
}

impl Default for TrinConfig {
    fn default() -> Self {
        TrinConfig {
            web3_transport: Web3TransportType::from_str(DEFAULT_WEB3_TRANSPORT)
                .expect("Parsing static DEFAULT_WEB3_TRANSPORT to work"),
            web3_http_address: Url::parse(DEFAULT_WEB3_HTTP_ADDRESS)
                .expect("Parsing static DEFAULT_WEB3_HTTP_ADDRESS to work"),
            web3_ipc_path: PathBuf::from(DEFAULT_WEB3_IPC_PATH),
            discovery_port: DEFAULT_DISCOVERY_PORT
                .parse()
                .expect("Parsing static DEFAULT_DISCOVERY_PORT to work"),
            bootnodes: Bootnodes::Default,
            external_addr: None,
            no_stun: false,
            private_key: None,
            networks: DEFAULT_SUBNETWORKS
                .split(',')
                .map(|n| n.to_string())
                .collect(),
            mb: DEFAULT_STORAGE_CAPACITY_MB
                .parse()
                .expect("Parsing static DEFAULT_STORAGE_CAPACITY_MB to work"),
            enable_metrics_with_url: None,
            ephemeral: false,
            trusted_provider: TrustedProviderType::Infura,
            trusted_provider_url: None,
            master_acc_path: PathBuf::from(DEFAULT_MASTER_ACC_PATH.to_string()),
            command: None,
        }
    }
}

impl TrinConfig {
    pub fn from_cli() -> Self {
        Self::new_from(env::args_os()).unwrap_or_else(|e| e.exit())
    }
    pub fn new_from<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: Iterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let config = Self::try_parse_from(args)?;

        if let Some(TrinConfigCommands::CreateDashboard(dashboard_config)) = config.command {
            if let Err(err) = create_dashboard(dashboard_config) {
                panic!("Creating dashboard failed {}", err);
            }
            // exit program since if the user uses create dashboard this is all we do
            std::process::exit(0);
        }

        match config.web3_transport {
            Web3TransportType::HTTP => match &config.web3_ipc_path.as_path().display().to_string()[..] {
                DEFAULT_WEB3_IPC_PATH => {}
                _ => panic!("Must not supply an ipc path when using http protocol for json-rpc"),
            },
            Web3TransportType::IPC => match config.web3_http_address.as_str() {
                DEFAULT_WEB3_HTTP_ADDRESS => {}
                p => panic!("Must not supply an http address when using ipc protocol for json-rpc (received: {p})"),
            }
        }

        match config.trusted_provider_url {
            Some(_) => {
                if config.trusted_provider == TrustedProviderType::Infura {
                    panic!("--trusted-provider-url flag is incompatible with infura as the trusted provider.")
                }
            }
            None => match config.trusted_provider {
                TrustedProviderType::Infura => {}
                TrustedProviderType::Pandaops => panic!(
                    "'--trusted-provider pandaops' choice requires the --trusted-provider-url flag."
                ),
                TrustedProviderType::Custom => panic!(
                    "'--trusted-provider custom' choice requires the --trusted-provider-url flag."
                ),
            },
        }
        // Should not serve http over same port as localhost provider.
        if config.web3_transport == Web3TransportType::HTTP
            && config.trusted_provider == TrustedProviderType::Custom
        {
            if let Some(url) = &config.trusted_provider_url {
                let is_local_provider = url.host_str() == Some("127.0.0.1");
                let port_clash = url.port() == config.web3_http_address.port();
                if is_local_provider && port_clash {
                    panic!("--trusted-provider-url and --web3-http-address cannot have the same localhost port.")
                }
            }
        }
        Ok(config)
    }
}

/// A validator function for CLI URL arguments.
fn check_url_format(url: &str) -> Result<Url, String> {
    match Url::parse(url) {
        Ok(val) => Ok(val),
        Err(e) => panic!("Invalid URL '{url}', {e}"),
    }
}

fn check_private_key_length(private_key: &str) -> Result<H256, String> {
    if private_key.len() == 66 {
        return H256::from_str(private_key).map_err(|err| format!("HexError: {}", err));
    }
    panic!(
        "Invalid private key length: {}, expected 66 (0x-prefixed 32 byte hexstring)",
        private_key.len()
    )
}

impl fmt::Display for TrinConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let web3_ipc_path_str = self.web3_ipc_path.as_path().display().to_string();
        let json_rpc_url = match &self.web3_transport {
            Web3TransportType::HTTP => self.web3_http_address.as_str(),
            Web3TransportType::IPC => &web3_ipc_path_str[..],
        };

        write!(
            f,
            "TrinConfig {{ networks: {:?}, capacity_mb: {}, ephemeral: {}, json_rpc_url: {}, metrics_enabled: {} }}",
            self.networks, self.mb, self.ephemeral, json_rpc_url, self.enable_metrics_with_url.is_some()
        )
    }
}

#[derive(Subcommand, Debug, Clone, PartialEq)]
#[allow(clippy::enum_variant_names)]
pub enum TrinConfigCommands {
    CreateDashboard(DashboardConfig),
}

#[derive(Args, Debug, Default, Clone, PartialEq)]
#[allow(clippy::enum_variant_names)]
pub struct DashboardConfig {
    #[arg(default_value = "http://localhost:3000")]
    pub grafana_address: String,

    #[arg(default_value = "admin")]
    pub grafana_username: String,

    #[arg(default_value = "admin")]
    pub grafana_password: String,

    #[arg(default_value = "http://host.docker.internal:9090")]
    pub prometheus_address: String,
}

pub fn create_dashboard(
    dashboard_config: DashboardConfig,
) -> Result<(), Box<dyn std::error::Error>> {
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use crate::types::provider::TrustedProvider;
    use std::env;
    use std::net::{IpAddr, Ipv4Addr};
    use test_log::test;

    fn env_is_set(config: &TrinConfig) -> bool {
        match config.trusted_provider {
            // Custom node does not require infura id.
            TrustedProviderType::Custom => return true,
            // Pandaops node does not require infura id.
            TrustedProviderType::Pandaops => return true,
            _ => {}
        }
        matches!(env::var("TRIN_INFURA_PROJECT_ID"), Ok(_))
    }

    #[test]
    fn test_default_args() {
        let expected_config = TrinConfig::default();
        let actual_config = TrinConfig::new_from(["trin"].iter()).unwrap();
        assert!(env_is_set(&actual_config));
        assert_eq!(actual_config.web3_transport, expected_config.web3_transport);
        assert_eq!(
            actual_config.web3_http_address,
            expected_config.web3_http_address
        );
        assert_eq!(actual_config.external_addr, expected_config.external_addr);
        assert_eq!(actual_config.no_stun, expected_config.no_stun);
        assert_eq!(actual_config.ephemeral, expected_config.ephemeral);
    }

    #[test]
    fn test_help() {
        TrinConfig::new_from(["trin", "-h"].iter()).expect_err("Should be an error to exit early");
    }

    #[test]
    fn test_custom_http_args() {
        let expected_config = TrinConfig {
            web3_http_address: Url::parse("http://0.0.0.0:8080/").unwrap(),
            web3_transport: Web3TransportType::HTTP,
            ..Default::default()
        };
        let actual_config = TrinConfig::new_from(
            [
                "trin",
                "--web3-transport",
                "http",
                "--web3-http-address",
                "http://0.0.0.0:8080/",
            ]
            .iter(),
        )
        .unwrap();
        assert!(env_is_set(&actual_config));
        assert_eq!(actual_config.web3_transport, expected_config.web3_transport);
        assert_eq!(
            actual_config.web3_http_address,
            expected_config.web3_http_address
        );
    }

    #[test]
    fn test_ipc_protocol() {
        let actual_config = Default::default();
        assert!(env_is_set(&actual_config));
        let expected_config = TrinConfig {
            web3_http_address: Url::parse(DEFAULT_WEB3_HTTP_ADDRESS).unwrap(),
            web3_transport: Web3TransportType::IPC,
            ..Default::default()
        };
        assert_eq!(actual_config.web3_transport, expected_config.web3_transport);
        assert_eq!(
            actual_config.web3_http_address,
            expected_config.web3_http_address
        );
    }

    #[test]
    fn test_ipc_with_custom_path() {
        let actual_config =
            TrinConfig::new_from(["trin", "--web3-ipc-path", "/path/test.ipc"].iter()).unwrap();
        assert!(env_is_set(&actual_config));
        let expected_config = TrinConfig {
            web3_http_address: Url::parse(DEFAULT_WEB3_HTTP_ADDRESS).unwrap(),
            web3_ipc_path: PathBuf::from("/path/test.ipc"),
            web3_transport: Web3TransportType::IPC,
            ..Default::default()
        };
        assert_eq!(actual_config.web3_transport, expected_config.web3_transport);
        assert_eq!(
            actual_config.web3_http_address,
            expected_config.web3_http_address
        );
        assert_eq!(actual_config.web3_ipc_path, expected_config.web3_ipc_path);
    }

    #[test]
    #[should_panic(expected = "Must not supply an ipc path when using http")]
    fn test_http_protocol_rejects_custom_web3_ipc_path() {
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
        TrinConfig::new_from(["trin", "--web3-http-address", "http://127.0.0.1:1234/"].iter())
            .unwrap_err();
    }

    #[test]
    fn test_custom_discovery_port() {
        let expected_config = TrinConfig {
            discovery_port: 999,
            ..Default::default()
        };
        let actual_config =
            TrinConfig::new_from(["trin", "--discovery-port", "999"].iter()).unwrap();
        assert!(env_is_set(&actual_config));
        assert_eq!(actual_config.discovery_port, expected_config.discovery_port);
    }

    #[test]
    fn test_manual_external_addr_v4() {
        let actual_config =
            TrinConfig::new_from(["trin", "--external-address", "127.0.0.1:1234"].iter()).unwrap();
        assert!(env_is_set(&actual_config));
        assert_eq!(
            actual_config.external_addr,
            Some(SocketAddr::from(([127, 0, 0, 1], 1234)))
        );
    }

    #[test]
    fn test_manual_external_addr_v6() {
        let actual_config =
            TrinConfig::new_from(["trin", "--external-address", "[::1]:1234"].iter()).unwrap();
        assert!(env_is_set(&actual_config));
        assert_eq!(
            actual_config.external_addr,
            Some(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 1234)))
        );
    }

    #[test]
    fn test_custom_private_key() {
        let expected_config = TrinConfig {
            private_key: Some(H256::from_slice(&[1; 32])),
            ..Default::default()
        };
        let actual_config = TrinConfig::new_from(
            [
                "trin",
                "--unsafe-private-key",
                "0x0101010101010101010101010101010101010101010101010101010101010101",
            ]
            .iter(),
        )
        .unwrap();
        assert!(env_is_set(&actual_config));
        assert_eq!(actual_config.private_key, expected_config.private_key);
    }

    #[test]
    fn test_ephemeral() {
        let expected_config = TrinConfig {
            ephemeral: true,
            ..Default::default()
        };
        let actual_config = TrinConfig::new_from(["trin", "--ephemeral"].iter()).unwrap();
        assert!(env_is_set(&actual_config));
        assert_eq!(actual_config.ephemeral, expected_config.ephemeral);
    }

    #[test]
    fn test_enable_metrics_with_url() {
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
        assert!(env_is_set(&actual_config));
        assert_eq!(
            actual_config.enable_metrics_with_url,
            expected_config.enable_metrics_with_url
        );
    }

    #[test]
    #[should_panic(
        expected = "Invalid private key length: 65, expected 66 (0x-prefixed 32 byte hexstring)"
    )]
    fn test_custom_private_key_odd_length() {
        TrinConfig::new_from(
            [
                "trin",
                "--unsafe-private-key",
                "0x010101010101010101010101010101010101010101010101010101010101010",
            ]
            .iter(),
        )
        .unwrap_err();
    }

    #[test]
    #[should_panic(
        expected = "Invalid private key length: 64, expected 66 (0x-prefixed 32 byte hexstring)"
    )]
    fn test_custom_private_key_requires_32_bytes() {
        TrinConfig::new_from(
            [
                "trin",
                "--unsafe-private-key",
                "0x01010101010101010101010101010101010101010101010101010101010101",
            ]
            .iter(),
        )
        .unwrap_err();
    }

    #[test]
    fn test_default_trusted_provider_is_infura() {
        let config = TrinConfig::new_from(["trin"].iter()).unwrap();
        assert!(env_is_set(&config));
        assert_eq!(config.trusted_provider, TrustedProviderType::Infura);
    }

    #[test]
    fn test_pandaops_trusted_provider() {
        let config = TrinConfig::new_from(
            [
                "trin",
                "--trusted-provider",
                "pandaops",
                "--trusted-provider-url",
                "https://www.geth.com/",
            ]
            .iter(),
        )
        .unwrap();
        assert!(env_is_set(&config));
        assert_eq!(config.trusted_provider, TrustedProviderType::Pandaops);
    }

    #[test]
    fn test_custom_local_node_trusted_provider() {
        let config = TrinConfig::new_from(
            [
                "trin",
                "--trusted-provider",
                "custom",
                "--trusted-provider-url",
                "http://127.0.0.1:8546/",
            ]
            .iter(),
        )
        .unwrap();
        assert!(env_is_set(&config));
        assert_eq!(config.trusted_provider, TrustedProviderType::Custom);
        let trusted_provider = TrustedProvider::from_trin_config(&config);
        let url: ureq::RequestUrl = trusted_provider.http.request_url().unwrap();
        assert_eq!(url.host(), "127.0.0.1");
        assert_eq!(url.port(), Some(8546));
    }

    #[test]
    fn test_trin_with_create_dashboard() {
        let config = TrinConfig::try_parse_from([
            "trin",
            "create-dashboard",
            "http://localhost:8787",
            "username",
            "password",
            "http://docker:9090",
        ])
        .unwrap();
        if let Some(TrinConfigCommands::CreateDashboard(dashboard_config)) = config.command {
            assert_eq!(
                dashboard_config.grafana_address,
                "http://localhost:8787".to_string()
            );
            assert_eq!(dashboard_config.grafana_username, "username".to_string());
            assert_eq!(dashboard_config.grafana_password, "password".to_string());
            assert_eq!(
                dashboard_config.prometheus_address,
                "http://docker:9090".to_string()
            );
        } else {
            unreachable!("")
        }
    }

    #[test]
    #[should_panic(
        expected = "--trusted-provider-url flag is incompatible with infura as the trusted provider."
    )]
    fn test_trusted_provider_url_must_not_be_used_with_infura_provider() {
        TrinConfig::new_from(["trin", "--trusted-provider-url", "http://127.0.0.1:8546/"].iter())
            .unwrap();
    }

    #[test]
    #[should_panic(
        expected = "'--trusted-provider custom' choice requires the --trusted-provider-url flag."
    )]
    fn test_custom_node_trusted_provider_requires_node_url() {
        TrinConfig::new_from(["trin", "--trusted-provider", "custom"].iter()).unwrap();
    }

    #[test]
    #[should_panic(
        expected = "--trusted-provider-url and --web3-http-address cannot have the same localhost port."
    )]
    fn test_web3_port_must_not_clash_with_local_provider_port() {
        TrinConfig::new_from(
            [
                "trin",
                "--trusted-provider",
                "custom",
                "--trusted-provider-url",
                "http://127.0.0.1:8545/",
                "--web3-transport",
                "http",
                "--web3-http-address",
                "http://127.0.0.1:8545/",
            ]
            .iter(),
        )
        .unwrap();
    }

    #[test]
    fn test_web3_port_different_from_local_provider_port() {
        TrinConfig::new_from(
            [
                "trin",
                "--trusted-provider",
                "custom",
                "--trusted-provider-url",
                "http://127.0.0.1:8545/",
                "--web3-transport",
                "http",
                "--web3-http-address",
                "http://127.0.0.1:8546/",
            ]
            .iter(),
        )
        .unwrap();
    }

    #[test]
    #[should_panic(
        expected = "'--trusted-provider pandaops' choice requires the --trusted-provider-url flag."
    )]
    fn test_pandaops_trusted_provider_requires_trusted_provider_url() {
        TrinConfig::new_from(["trin", "--trusted-provider", "pandaops"].iter()).unwrap();
    }

    #[test]
    #[should_panic(expected = "Invalid trusted provider arg")]
    fn test_trusted_provider_invalid_argument() {
        TrinConfig::new_from(["trin", "--trusted-provider", "prysm"].iter()).unwrap();
    }

    #[test]
    #[should_panic(expected = "Invalid URL 'www.geth.com', relative URL without a base")]
    fn test_pandaops_malformed_url_fails() {
        TrinConfig::new_from(["trin", "--trusted-provider-url", "www.geth.com"].iter()).unwrap();
    }

    #[test]
    #[should_panic(
        expected = "--trusted-provider-url flag is incompatible with infura as the trusted provider."
    )]
    fn test_provider_url_invalid_with_infura_as_trusted_provider() {
        TrinConfig::new_from(
            [
                "trin",
                "--trusted-provider",
                "infura",
                "--trusted-provider-url",
                "https://www.geth.com/",
            ]
            .iter(),
        )
        .unwrap();
    }

    #[test]
    #[should_panic(expected = "Invalid web3-transport arg. Expected either 'http' or 'ipc'")]
    fn test_invalid_web3_transport_argument() {
        TrinConfig::new_from(["trin", "--web3-transport", "invalid"].iter()).unwrap();
    }
}
