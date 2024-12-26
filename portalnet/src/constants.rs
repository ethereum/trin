use std::time::Duration;

/// The default timeout for a query.
///
/// A "query" here refers to the whole process for finding a single piece of Portal content, across
/// all peer interactions. A single RPC request may spawn many queries. Each query will typically
/// spawn many requests to peers.
pub const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(60);

pub const DEFAULT_WEB3_IPC_PATH: &str = "/tmp/trin-jsonrpc.ipc";
pub const DEFAULT_WEB3_HTTP_ADDRESS: &str = "http://127.0.0.1:8545/";
pub const DEFAULT_WEB3_HTTP_PORT: u16 = 8545;
pub const DEFAULT_WEB3_WS_PORT: u16 = 8546;
pub const DEFAULT_DISCOVERY_PORT: u16 = 9009;
pub const DEFAULT_UTP_TRANSFER_LIMIT: usize = 50;
pub const DEFAULT_NETWORK: &str = "mainnet";
