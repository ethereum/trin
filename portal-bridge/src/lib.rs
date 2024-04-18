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

// PANDAOPS refers to the group of clients provisioned by the EF devops team.
// These are only intended to be used by core team members who have access to the nodes.
//
/// Execution layer PandaOps endpoint
// This endpoint points towards an archive node (erigon) and skips dshackle (by using el-cl url
// format), shackle is known to be somewhat buggy has caused some invalid responses.
// Reth's archive node, has also exhibited some problems with the concurrent requests rate we
// currently use.
pub const DEFAULT_BASE_EL_ENDPOINT: &str = "https://geth-lighthouse.mainnet.eu1.ethpandaops.io/";
pub const FALLBACK_BASE_EL_ENDPOINT: &str = "https://geth-lighthouse.mainnet.eu1.ethpandaops.io/";
/// Consensus layer PandaOps endpoint
/// We use Nimbus as the CL client, because it supports light client data by default.
pub const DEFAULT_BASE_CL_ENDPOINT: &str = "https://nimbus.mainnet.eu1.ethpandaops.io/";
pub const FALLBACK_BASE_CL_ENDPOINT: &str = "https://nimbus.mainnet.eu1.ethpandaops.io/";
