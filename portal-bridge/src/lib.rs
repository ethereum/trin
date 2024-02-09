#![warn(clippy::unwrap_used)]
#![warn(clippy::uninlined_format_args)]

pub mod api;
pub mod bridge;
pub mod cli;
pub mod client_handles;
pub mod constants;
pub mod gossip;
pub mod stats;
pub mod types;
pub mod utils;

use lazy_static::lazy_static;
use std::env;

// PANDAOPS refers to the group of clients provisioned by the EF devops team.
// These are only intended to be used by core team members who have access to the nodes.
//
/// Execution layer PandaOps endpoint
// This endpoint points towards an archive node (erigon) and skips dshackle (by using el-cl url
// format), shackle is known to be somewhat buggy has caused some invalid responses.
// Reth's archive node, has also exhibited some problems with the concurrent requests rate we
// currently use.
const DEFAULT_BASE_EL_ENDPOINT: &str = "https://geth-lighthouse.mainnet.eu1.ethpandaops.io/";
// The `erigon` endpoint appears to perform much better for backfill requests.
const DEFAULT_BASE_EL_ARCHIVE_ENDPOINT: &str =
    "https://erigon-lighthouse.mainnet.eu1.ethpandaops.io/";
/// Consensus layer PandaOps endpoint
/// We use Nimbus as the CL client, because it supports light client data by default.
const DEFAULT_BASE_CL_ENDPOINT: &str = "https://nimbus.mainnet.ethpandaops.io/";

lazy_static! {
    pub static ref PANDAOPS_CLIENT_ID: String =
        env::var("PANDAOPS_CLIENT_ID").expect("PANDAOPS_CLIENT_ID env var not set.");
    pub static ref PANDAOPS_CLIENT_SECRET: String =
        env::var("PANDAOPS_CLIENT_SECRET").expect("PANDAOPS_CLIENT_SECRET env var not set.");
    static ref BASE_EL_ENDPOINT: String =
        env::var("BASE_EL_ENDPOINT").unwrap_or_else(|_| DEFAULT_BASE_EL_ENDPOINT.to_string());
    static ref BASE_EL_ARCHIVE_ENDPOINT: String = env::var("BASE_EL_ARCHIVE_ENDPOINT")
        .unwrap_or_else(|_| DEFAULT_BASE_EL_ARCHIVE_ENDPOINT.to_string());
    static ref BASE_CL_ENDPOINT: String =
        env::var("BASE_CL_ENDPOINT").unwrap_or_else(|_| DEFAULT_BASE_CL_ENDPOINT.to_string());
}
