// Copied from bin/portal-bridge/src/api/consensus/constants.rs

use tokio::time::Duration;

/// The timeout in seconds is applied when requesting the beacon state from the Beacon API
pub const DEFAULT_BEACON_STATE_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
