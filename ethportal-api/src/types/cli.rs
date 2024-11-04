use alloy::primitives::B256;
use clap::{
    arg,
    builder::ArgPredicate,
    error::{Error, ErrorKind},
    Args, Parser, Subcommand,
};
use std::{env, ffi::OsString, fmt, net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};
use url::Url;

use crate::{
    build_info,
    types::{bootnodes::Bootnodes, network::Subnetwork},
};

pub const DEFAULT_WEB3_IPC_PATH: &str = "/tmp/trin-jsonrpc.ipc";
pub const DEFAULT_WEB3_HTTP_ADDRESS: &str = "http://127.0.0.1:8545/";
pub const DEFAULT_WEB3_HTTP_PORT: u16 = 8545;
pub const DEFAULT_WEB3_WS_PORT: u16 = 8546;
pub const DEFAULT_DISCOVERY_PORT: u16 = 9009;
pub const DEFAULT_UTP_TRANSFER_LIMIT: usize = 50;
const DEFAULT_SUBNETWORKS: &str = "history";
pub const DEFAULT_NETWORK: &str = "mainnet";
pub const DEFAULT_STORAGE_CAPACITY_MB: &str = "1000";
pub const DEFAULT_WEB3_TRANSPORT: &str = "ipc";

use crate::dashboard::grafana::{GrafanaAPI, DASHBOARD_TEMPLATES};

use super::portal_wire::{NetworkSpec, ANGELFOOD, MAINNET};

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

const APP_NAME: &str = "trin";
const VERSION: &str = const_format::formatcp!(
    "{version}-{hash} {build_os} {rust_version}",
    // Remove -alpha.1 versioning if it is present.
    // This must be done as it can conflict with eth versioning
    version = const_format::str_split!(build_info::PKG_VERSION, '-')[0],
    hash = build_info::short_commit(),
    build_os = build_info::BUILD_OS,
    // the rust version looks like that:
    // rustc 1.77.0 (aedd173a2 2024-03-17)
    // we remove everything in the brackets and replace spaces with nothing
    rust_version = const_format::str_replace!(
        const_format::str_split!(build_info::RUST_VERSION, '(')[0],
        ' ',
        ""
    )
);

/// The storage capacity configurtion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageCapacityConfig {
    Combined {
        total_mb: u32,
        subnetworks: Vec<Subnetwork>,
    },
    Specific {
        beacon_mb: Option<u32>,
        history_mb: Option<u32>,
        state_mb: Option<u32>,
    },
}

#[derive(Parser, Debug, PartialEq, Clone)]
#[command(name = APP_NAME,
    author = "https://github.com/ethereum/trin/graphs/contributors",
    about = "Run an eth portal client",
    version = VERSION)]
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
        default_value_t = DEFAULT_DISCOVERY_PORT,
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
        long = "no-upnp",
        help = "Do not use UPnP to determine an external port."
    )]
    pub no_upnp: bool,

    #[arg(
        long = "unsafe-private-key",
        value_parser = check_private_key_length,
        help = "Hex encoded 32 byte private key (with 0x prefix) (considered unsafe as it's stored in terminal history - keyfile support coming soon)"
    )]
    pub private_key: Option<B256>,

    #[arg(
        long,
        value_parser = check_trusted_block_root,
        help = "Hex encoded block root from a trusted checkpoint"
    )]
    pub trusted_block_root: Option<B256>,

    #[arg(
        long,
        help = "Choose mainnet or angelfood",
        default_value = DEFAULT_NETWORK,
        value_parser = network_parser
    )]
    pub network: Arc<NetworkSpec>,

    #[arg(
        long,
        help = "Comma-separated list of which portal subnetworks to activate",
        default_value = DEFAULT_SUBNETWORKS,
        value_parser = subnetwork_parser,
    )]
    pub portal_subnetworks: Arc<Vec<Subnetwork>>,

    #[arg(
        id = "storage.total",
        long = "storage.total",
        alias = "mb",
        help = "Maximum storage capacity (in megabytes), shared between enabled subnetworks",
        long_help = "Maximum storage capacity (in megabytes), shared between enabled subnetworks.\nCan't be used in combination with 'storage.{subnetwork}' flags (if storage of one subnetwork is specified explicitly, all have to be). If none of the flags is used, then `storage.total` is used with default value.\nThe actual storage can be higher than specified, due to overhead.",
        default_value_if("storage.beacon", ArgPredicate::IsPresent, None),
        default_value_if("storage.history", ArgPredicate::IsPresent, None),
        default_value_if("storage.state", ArgPredicate::IsPresent, None),
        default_value = Some(DEFAULT_STORAGE_CAPACITY_MB),
    )]
    pub storage_total: Option<u32>,

    #[arg(
        id = "storage.beacon",
        long = "storage.beacon",
        help = "Maximum storage capacity (in megabytes) used by beacon subnetwork",
        long_help = "Maximum storage capacity (in megabytes) used by beacon subnetwork.\nCan't be used in combination with 'storage.total' flag.\nThe actual storage can be higher than specified, due to overhead."
    )]
    pub storage_beacon: Option<u32>,

    #[arg(
        id = "storage.history",
        long = "storage.history",
        help = "Maximum storage capacity (in megabytes) used by history subnetwork",
        long_help = "Maximum storage capacity (in megabytes) used by history subnetwork.\nCan't be used in combination with 'storage.total' flag.\nThe actual storage can be higher than specified, due to overhead."
    )]
    pub storage_history: Option<u32>,

    #[arg(
        id = "storage.state",
        long = "storage.state",
        help = "Maximum storage capacity (in megabytes) used by state subnetwork",
        long_help = "Maximum storage capacity (in megabytes) used by state subnetwork.\nCan't be used in combination with 'storage.total' flag.\nThe actual storage can be higher than specified, due to overhead."
    )]
    pub storage_state: Option<u32>,

    #[arg(
        long = "enable-metrics-with-url",
        help = "Enable prometheus metrics reporting (provide local IP/Port from which your Prometheus server is configured to fetch metrics)"
    )]
    pub enable_metrics_with_url: Option<SocketAddr>,

    #[arg(
        long,
        help = "The directory for storing application data. If used together with --ephemeral, new child directory will be created. Can be alternatively set via TRIN_DATA_PATH env variable."
    )]
    pub data_dir: Option<PathBuf>,

    #[arg(
        long,
        short,
        help = "Use new data directory, located in OS temporary directory. If used together with --data-dir, new directory will be created there instead."
    )]
    pub ephemeral: bool,

    #[arg(
        long = "disable-poke",
        help = "Disables the poke mechanism, which propagates content at the end of a successful content query. Disabling is useful for network analysis purposes."
    )]
    pub disable_poke: bool,

    #[arg(long = "ws", help = "Used to enable WebSocket rpc.")]
    pub ws: bool,

    #[arg(
        long = "ws-port", 
        help = "The WebSocket port to listen on.", 
        default_value_t = DEFAULT_WEB3_WS_PORT,
        requires = "ws"
    )]
    pub ws_port: u16,

    #[arg(
        long = "utp-transfer-limit", 
        help = "The limit of max background uTP transfers for any given channel (inbound or outbound) for each subnetwork", 
        default_value_t = DEFAULT_UTP_TRANSFER_LIMIT,
    )]
    pub utp_transfer_limit: usize,

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
            discovery_port: DEFAULT_DISCOVERY_PORT,
            bootnodes: Bootnodes::Default,
            external_addr: None,
            no_stun: false,
            no_upnp: false,
            private_key: None,
            trusted_block_root: None,
            portal_subnetworks: subnetwork_parser(DEFAULT_SUBNETWORKS)
                .expect("Parsing static DEFAULT_SUBNETWORKS to work"),
            storage_total: DEFAULT_STORAGE_CAPACITY_MB.parse().ok(),
            storage_beacon: None,
            storage_history: None,
            storage_state: None,
            enable_metrics_with_url: None,
            data_dir: None,
            ephemeral: false,
            disable_poke: false,
            ws: false,
            ws_port: DEFAULT_WEB3_WS_PORT,
            command: None,
            utp_transfer_limit: DEFAULT_UTP_TRANSFER_LIMIT,
            network: MAINNET.clone(),
        }
    }
}

impl TrinConfig {
    pub fn from_cli() -> Self {
        Self::new_from(env::args_os()).unwrap_or_else(|e| e.exit())
    }

    pub fn new_from<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let config = Self::try_parse_from(args)?;

        if let Some(TrinConfigCommands::CreateDashboard(dashboard_config)) = config.command {
            if let Err(err) = create_dashboard(dashboard_config) {
                panic!("Creating dashboard failed {err}");
            }
            // exit program since if the user uses create dashboard this is all we do
            std::process::exit(0);
        }

        match config.web3_transport {
            Web3TransportType::HTTP => {
                match &config.web3_ipc_path.as_path().display().to_string()[..] {
                    DEFAULT_WEB3_IPC_PATH => {}
                    _ => {
                        return Err(Error::raw(
                            ErrorKind::ArgumentConflict,
                            "Must not supply an ipc path when using http protocol for json-rpc",
                        ))
                    }
                }
            }
            Web3TransportType::IPC => {
                match config.web3_http_address.as_str() {
                    DEFAULT_WEB3_HTTP_ADDRESS => {}
                    web3_http_address => {
                        return Err(Error::raw(
                            ErrorKind::ArgumentConflict,
                            format!("Must not supply an http address when using ipc protocol for json-rpc (received: {web3_http_address})"),
                        ))
                    },
                }
                if config.ws {
                    return Err(Error::raw(
                        ErrorKind::ArgumentConflict,
                        format!(
                            "Must not enable ws when using ipc protocol for json-rpc (received: {})",
                            config.web3_http_address.as_str(),
                        ),
                    ));
                }
            }
        }

        if config.portal_subnetworks.contains(&Subnetwork::State)
            && !config.portal_subnetworks.contains(&Subnetwork::History)
        {
            return Err(Error::raw(
                ErrorKind::ValueValidation,
                "State subnetwork can only be enabled together with history.",
            ));
        }

        match config.storage_total {
            Some(_) => {
                // If storage.total is set, we should make sure that none of the storage.* flags,
                // is set as well.
                if config.storage_beacon.is_some() {
                    return Err(Error::raw(
                        ErrorKind::ArgumentConflict,
                        "--storage.total and --storage.beacon can't be set at the same time",
                    ));
                }
                if config.storage_history.is_some() {
                    return Err(Error::raw(
                        ErrorKind::ArgumentConflict,
                        "--storage.total and --storage.history can't be set at the same time",
                    ));
                }
                if config.storage_state.is_some() {
                    return Err(Error::raw(
                        ErrorKind::ArgumentConflict,
                        "--storage.total and --storage.state can't be set at the same time",
                    ));
                }
            }
            None => {
                // If storage.total is None, that means that at least one storage.* flag is set,
                // And we have to check that enabled subnetworks match storage.* flags
                let subnetwork_check = |subnetwork: Subnetwork,
                                        storage_flag: Option<u32>|
                 -> Result<(), clap::Error> {
                    if config.portal_subnetworks.contains(&subnetwork) && storage_flag.is_none() {
                        return Err(Error::raw(
                            ErrorKind::ArgumentConflict,
                            format!(
                                "{subnetwork} subnetwork enabled but --storage.{} is not set",
                                subnetwork.to_cli_arg(),
                            ),
                        ));
                    }
                    if storage_flag.is_some() && !config.portal_subnetworks.contains(&subnetwork) {
                        return Err(Error::raw(
                            ErrorKind::ArgumentConflict,
                            format!(
                                "--storage.{} is set but {subnetwork} subnetwork is not enabled",
                                subnetwork.to_cli_arg(),
                            ),
                        ));
                    }
                    Ok(())
                };
                subnetwork_check(Subnetwork::Beacon, config.storage_beacon)?;
                subnetwork_check(Subnetwork::History, config.storage_history)?;
                subnetwork_check(Subnetwork::State, config.storage_state)?;
            }
        }

        Ok(config)
    }

    pub fn storage_capacity_config(&self) -> StorageCapacityConfig {
        match self.storage_total {
            Some(total_mb) => StorageCapacityConfig::Combined {
                total_mb,
                subnetworks: (*self.portal_subnetworks).clone(),
            },
            None => StorageCapacityConfig::Specific {
                beacon_mb: self.storage_beacon,
                history_mb: self.storage_history,
                state_mb: self.storage_state,
            },
        }
    }
}

pub fn check_private_key_length(private_key: &str) -> Result<B256, String> {
    if private_key.len() == 66 {
        return B256::from_str(private_key).map_err(|err| format!("HexError: {err}"));
    }
    Err(format!(
        "Invalid private key length: {}, expected 66 (0x-prefixed 32 byte hexstring)",
        private_key.len()
    ))
}

pub fn network_parser(network_string: &str) -> Result<Arc<NetworkSpec>, String> {
    match network_string {
        "mainnet" => Ok(MAINNET.clone()),
        "angelfood" => Ok(ANGELFOOD.clone()),
        _ => Err(format!(
            "Not a valid network: {network_string}, must be 'angelfood' or 'mainnet'"
        )),
    }
}

pub fn subnetwork_parser(subnetwork_string: &str) -> Result<Arc<Vec<Subnetwork>>, String> {
    let subnetworks = subnetwork_string
        .split(',')
        .map(Subnetwork::from_cli_arg)
        .collect::<Result<Vec<Subnetwork>, String>>()?;

    if subnetworks.is_empty() {
        return Err("At least one subnetwork must be enabled".to_owned());
    }

    for subnetwork in &subnetworks {
        if !subnetwork.is_active() {
            return Err("{subnetwork} subnetwork has not yet been activated".to_owned());
        }
    }

    Ok(Arc::new(subnetworks))
}

fn check_trusted_block_root(trusted_root: &str) -> Result<B256, String> {
    if !trusted_root.starts_with("0x") {
        return Err("Trusted block root must be prefixed with 0x".to_owned());
    }

    if trusted_root.len() == 66 {
        return B256::from_str(trusted_root).map_err(|err| format!("HexError: {err}"));
    }
    Err(format!(
        "Invalid trusted block root length: {}, expected 66 (0x-prefixed 32 byte hexstring)",
        trusted_root.len()
    ))
}

impl fmt::Display for TrinConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let web3_ipc_path_str = self.web3_ipc_path.as_path().display().to_string();
        let json_rpc_url = match &self.web3_transport {
            Web3TransportType::HTTP => self.web3_http_address.as_str(),
            Web3TransportType::IPC => &web3_ipc_path_str[..],
        };

        f.debug_struct("TrinConfig")
            .field("subnetworks", &self.portal_subnetworks)
            .field("storage.total", &self.storage_total)
            .field("storage.beacon", &self.storage_beacon)
            .field("storage.history", &self.storage_history)
            .field("storage.state", &self.storage_state)
            .field("ephemeral", &self.ephemeral)
            .field("json_rpc_url", &json_rpc_url)
            .field("metrics_enabled", &self.enable_metrics_with_url.is_some())
            .finish()
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
    for template_path in DASHBOARD_TEMPLATES {
        let dashboard_url = grafana.create_dashboard(template_path, &prometheus_uid)?;
        println!("Dashboard successfully created: {dashboard_url}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use test_log::test;

    use super::*;

    #[test]
    fn test_default_args() {
        let expected_config = TrinConfig::default();
        let actual_config = TrinConfig::new_from(["trin"]).unwrap();
        assert_eq!(actual_config.web3_transport, expected_config.web3_transport);
        assert_eq!(
            actual_config.web3_http_address,
            expected_config.web3_http_address
        );
        assert_eq!(actual_config.external_addr, expected_config.external_addr);
        assert_eq!(actual_config.no_stun, expected_config.no_stun);
        assert_eq!(actual_config.no_upnp, expected_config.no_upnp);
        assert_eq!(actual_config.ephemeral, expected_config.ephemeral);
    }

    #[test]
    fn test_help() {
        TrinConfig::new_from(["trin", "-h"]).expect_err("Should be an error to exit early");
    }

    #[test]
    fn test_custom_http_args() {
        let expected_config = TrinConfig {
            web3_http_address: Url::parse("http://0.0.0.0:8080/").unwrap(),
            web3_transport: Web3TransportType::HTTP,
            ..Default::default()
        };
        let actual_config = TrinConfig::new_from([
            "trin",
            "--web3-transport",
            "http",
            "--web3-http-address",
            "http://0.0.0.0:8080/",
        ])
        .unwrap();
        assert_eq!(actual_config.web3_transport, expected_config.web3_transport);
        assert_eq!(
            actual_config.web3_http_address,
            expected_config.web3_http_address
        );
    }

    #[test]
    fn test_ipc_protocol() {
        let actual_config: TrinConfig = Default::default();
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
            TrinConfig::new_from(["trin", "--web3-ipc-path", "/path/test.ipc"]).unwrap();
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
        TrinConfig::new_from([
            "trin",
            "--web3-transport",
            "http",
            "--web3-ipc-path",
            "/path/test.ipc",
        ])
        .unwrap();
    }

    #[test]
    #[should_panic(expected = "Must not supply an http address when using ipc")]
    fn test_ipc_protocol_rejects_custom_web3_http_address() {
        TrinConfig::new_from(["trin", "--web3-http-address", "http://127.0.0.1:1234/"]).unwrap();
    }

    #[test]
    fn test_custom_discovery_port() {
        let expected_config = TrinConfig {
            discovery_port: 999,
            ..Default::default()
        };
        let actual_config = TrinConfig::new_from(["trin", "--discovery-port", "999"]).unwrap();
        assert_eq!(actual_config.discovery_port, expected_config.discovery_port);
    }

    #[test]
    fn test_manual_external_addr_v4() {
        let actual_config =
            TrinConfig::new_from(["trin", "--external-address", "127.0.0.1:1234"]).unwrap();
        assert_eq!(
            actual_config.external_addr,
            Some(SocketAddr::from(([127, 0, 0, 1], 1234)))
        );
    }

    #[test]
    fn test_manual_external_addr_v6() {
        let actual_config =
            TrinConfig::new_from(["trin", "--external-address", "[::1]:1234"]).unwrap();
        assert_eq!(
            actual_config.external_addr,
            Some(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 1234)))
        );
    }

    #[test]
    fn test_custom_private_key() {
        let expected_config = TrinConfig {
            private_key: Some(B256::from_slice(&[1; 32])),
            ..Default::default()
        };
        let actual_config = TrinConfig::new_from([
            "trin",
            "--unsafe-private-key",
            "0x0101010101010101010101010101010101010101010101010101010101010101",
        ])
        .unwrap();
        assert_eq!(actual_config.private_key, expected_config.private_key);
    }

    #[test]
    fn test_ephemeral() {
        let expected_config = TrinConfig {
            ephemeral: true,
            ..Default::default()
        };
        let actual_config = TrinConfig::new_from(["trin", "--ephemeral"]).unwrap();
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
            TrinConfig::new_from(["trin", "--enable-metrics-with-url", "127.0.0.1:1234"]).unwrap();
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
        TrinConfig::new_from([
            "trin",
            "--unsafe-private-key",
            "0x010101010101010101010101010101010101010101010101010101010101010",
        ])
        .unwrap();
    }

    #[test]
    #[should_panic(
        expected = "Invalid private key length: 64, expected 66 (0x-prefixed 32 byte hexstring)"
    )]
    fn test_custom_private_key_requires_32_bytes() {
        TrinConfig::new_from([
            "trin",
            "--unsafe-private-key",
            "0x01010101010101010101010101010101010101010101010101010101010101",
        ])
        .unwrap();
    }

    #[test]
    #[should_panic(
        expected = "Invalid trusted block root length: 64, expected 66 (0x-prefixed 32 byte hexstring)"
    )]
    fn test_trusted_block_root_requires_32_bytes() {
        TrinConfig::new_from([
            "trin",
            "--trusted-block-root",
            "0x01010101010101010101010101010101010101010101010101010101010101",
        ])
        .unwrap();
    }

    #[test]
    #[should_panic(expected = "Trusted block root must be prefixed with 0x")]
    fn test_trusted_block_root_starts_with_0x() {
        TrinConfig::new_from([
            "trin",
            "--trusted-block-root",
            "010101010101010101010101010101010101010101010101010101010101010101",
        ])
        .unwrap();
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
    #[should_panic(expected = "Invalid web3-transport arg. Expected either 'http' or 'ipc'")]
    fn test_invalid_web3_transport_argument() {
        TrinConfig::new_from(["trin", "--web3-transport", "invalid"]).unwrap();
    }

    mod storage_config {
        use test_log::test;

        use super::*;

        #[test]
        fn no_flags() {
            let config = TrinConfig::new_from(["trin"]).unwrap();
            assert_eq!(
                config.storage_capacity_config(),
                StorageCapacityConfig::Combined {
                    total_mb: 1000,
                    subnetworks: vec![Subnetwork::History],
                }
            );
        }

        #[test]
        fn with_subnetworks() {
            let config =
                TrinConfig::new_from(["trin", "--portal-subnetworks", "history,state"]).unwrap();
            assert_eq!(
                config.storage_capacity_config(),
                StorageCapacityConfig::Combined {
                    total_mb: 1000,
                    subnetworks: vec![Subnetwork::History, Subnetwork::State],
                }
            );
        }

        #[test]
        fn with_total() {
            let config = TrinConfig::new_from(["trin", "--storage.total", "200"]).unwrap();
            assert_eq!(
                config.storage_capacity_config(),
                StorageCapacityConfig::Combined {
                    total_mb: 200,
                    subnetworks: vec![Subnetwork::History],
                }
            );
        }

        #[test]
        fn with_total_and_subnetworks() {
            let config = TrinConfig::new_from([
                "trin",
                "--storage.total",
                "200",
                "--portal-subnetworks",
                "history,state",
            ])
            .unwrap();
            assert_eq!(
                config.storage_capacity_config(),
                StorageCapacityConfig::Combined {
                    total_mb: 200,
                    subnetworks: vec![Subnetwork::History, Subnetwork::State],
                }
            );
        }

        #[test]
        fn with_mb() {
            let config = TrinConfig::new_from(["trin", "--mb", "200"]).unwrap();
            assert_eq!(
                config.storage_capacity_config(),
                StorageCapacityConfig::Combined {
                    total_mb: 200,
                    subnetworks: vec![Subnetwork::History],
                }
            );
        }

        #[test]
        fn with_mb_and_subnetworks() {
            let config = TrinConfig::new_from([
                "trin",
                "--mb",
                "200",
                "--portal-subnetworks",
                "history,state",
            ])
            .unwrap();
            assert_eq!(
                config.storage_capacity_config(),
                StorageCapacityConfig::Combined {
                    total_mb: 200,
                    subnetworks: vec![Subnetwork::History, Subnetwork::State],
                }
            );
        }

        #[test]
        fn with_total_and_all_subnetworks() {
            let config = TrinConfig::new_from([
                "trin",
                "--storage.total",
                "200",
                "--portal-subnetworks",
                "beacon,history,state",
            ])
            .unwrap();
            assert_eq!(
                config.storage_capacity_config(),
                StorageCapacityConfig::Combined {
                    total_mb: 200,
                    subnetworks: vec![Subnetwork::Beacon, Subnetwork::History, Subnetwork::State],
                }
            );
        }

        #[test]
        #[should_panic(
            expected = "--storage.total and --storage.beacon can't be set at the same time"
        )]
        fn with_total_and_beacon() {
            TrinConfig::new_from(["trin", "--storage.total", "200", "--storage.beacon", "100"])
                .unwrap();
        }

        #[test]
        #[should_panic(
            expected = "--storage.total and --storage.history can't be set at the same time"
        )]
        fn with_total_and_history() {
            TrinConfig::new_from(["trin", "--storage.total", "200", "--storage.history", "100"])
                .unwrap();
        }

        #[test]
        #[should_panic(
            expected = "--storage.total and --storage.state can't be set at the same time"
        )]
        fn with_total_and_state() {
            TrinConfig::new_from(["trin", "--storage.total", "200", "--storage.state", "100"])
                .unwrap();
        }

        #[test]
        fn with_history() {
            let config = TrinConfig::new_from(["trin", "--storage.history", "200"]).unwrap();
            assert_eq!(
                config.storage_capacity_config(),
                StorageCapacityConfig::Specific {
                    beacon_mb: None,
                    history_mb: Some(200),
                    state_mb: None,
                }
            );
        }

        #[test]
        fn with_history_and_state() {
            let config = TrinConfig::new_from([
                "trin",
                "--storage.history",
                "200",
                "--storage.state",
                "300",
                "--portal-subnetworks",
                "history,state",
            ])
            .unwrap();
            assert_eq!(
                config.storage_capacity_config(),
                StorageCapacityConfig::Specific {
                    beacon_mb: None,
                    history_mb: Some(200),
                    state_mb: Some(300),
                }
            );
        }

        #[test]
        fn with_history_and_state_and_beacon() {
            let config = TrinConfig::new_from([
                "trin",
                "--storage.history",
                "200",
                "--storage.state",
                "300",
                "--storage.beacon",
                "400",
                "--portal-subnetworks",
                "history,state,beacon",
            ])
            .unwrap();
            assert_eq!(
                config.storage_capacity_config(),
                StorageCapacityConfig::Specific {
                    beacon_mb: Some(400),
                    history_mb: Some(200),
                    state_mb: Some(300),
                }
            );
        }

        #[test]
        #[should_panic(expected = "--storage.state is set but State subnetwork is not enabled")]
        fn with_history_and_state_without_subnetworks() {
            TrinConfig::new_from(["trin", "--storage.history", "200", "--storage.state", "300"])
                .unwrap();
        }

        #[test]
        #[should_panic(expected = "--storage.beacon is set but Beacon subnetwork is not enabled")]
        fn with_history_and_beacon_without_subnetworks() {
            TrinConfig::new_from([
                "trin",
                "--storage.history",
                "200",
                "--storage.beacon",
                "300",
            ])
            .unwrap();
        }

        #[test]
        #[should_panic(expected = "--storage.history is set but History subnetwork is not enabled")]
        fn with_history_and_beacon_without_history_subnetwork() {
            TrinConfig::new_from([
                "trin",
                "--storage.history",
                "200",
                "--storage.beacon",
                "300",
                "--portal-subnetworks",
                "beacon",
            ])
            .unwrap();
        }

        #[test]
        #[should_panic(expected = "History subnetwork enabled but --storage.history is not set")]
        fn specific_without_history_with_subnetwork() {
            TrinConfig::new_from([
                "trin",
                "--storage.state",
                "200",
                "--portal-subnetworks",
                "history,state",
            ])
            .unwrap();
        }

        #[test]
        #[should_panic(expected = "State subnetwork enabled but --storage.state is not set")]
        fn specific_without_state_with_subnetwork() {
            TrinConfig::new_from([
                "trin",
                "--storage.history",
                "200",
                "--portal-subnetworks",
                "history,state",
            ])
            .unwrap();
        }

        #[test]
        #[should_panic(expected = "Beacon subnetwork enabled but --storage.beacon is not set")]
        fn specific_without_beacon_with_subnetwork() {
            TrinConfig::new_from([
                "trin",
                "--storage.history",
                "200",
                "--portal-subnetworks",
                "history,beacon",
            ])
            .unwrap();
        }

        #[test]
        fn with_total_zero() {
            let config = TrinConfig::new_from([
                "trin",
                "--storage.total",
                "0",
                "--portal-subnetworks",
                "history,state,beacon",
            ])
            .unwrap();
            assert_eq!(
                config.storage_capacity_config(),
                StorageCapacityConfig::Combined {
                    total_mb: 0,
                    subnetworks: vec![Subnetwork::History, Subnetwork::State, Subnetwork::Beacon]
                }
            );
        }

        #[test]
        fn with_zero_per_subnetwork() {
            let config = TrinConfig::new_from([
                "trin",
                "--storage.history",
                "0",
                "--storage.state",
                "0",
                "--storage.beacon",
                "0",
                "--portal-subnetworks",
                "history,state,beacon",
            ])
            .unwrap();
            assert_eq!(
                config.storage_capacity_config(),
                StorageCapacityConfig::Specific {
                    beacon_mb: Some(0),
                    history_mb: Some(0),
                    state_mb: Some(0),
                }
            );
        }
    }
}
