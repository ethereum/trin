use std::time::Duration;

/// The default timeout for a query.
///
/// A "query" here refers to the whole process for finding a single piece of Portal content, across
/// all peer interactions. A single RPC request may spawn many queries. Each query will typically
/// spawn many requests to peers.
pub const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(60);
