use tokio::time::Duration;

/// The timeout in seconds is applied from when the request starts connecting until the response
/// body has finished. Also considered a total deadline.
pub const DEFAULT_TOTAL_REQUEST_TIMEOUT: u64 = 20;

// Number of seconds to wait before retrying a provider request
pub const FALLBACK_RETRY_AFTER: Duration = Duration::from_secs(5);

pub const DEFAULT_BASE_EL_ENDPOINT: &str = "https://geth-lighthouse.mainnet.eu1.ethpandaops.io/";

