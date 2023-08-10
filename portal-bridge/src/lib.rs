#![warn(clippy::unwrap_used)]

pub mod beacon_bridge;
pub mod bridge;
pub mod cli;
pub mod client_handles;
pub mod consensus_api;
pub mod constants;
pub mod full_header;
pub mod mode;
pub mod pandaops;
pub mod types;
pub mod utils;

use lazy_static::lazy_static;
use std::env;

lazy_static! {
    static ref PANDAOPS_CLIENT_ID: String =
        env::var("PANDAOPS_CLIENT_ID").expect("PANDAOPS_CLIENT_ID env var not set.");
    static ref PANDAOPS_CLIENT_SECRET: String =
        env::var("PANDAOPS_CLIENT_SECRET").expect("PANDAOPS_CLIENT_SECRET env var not set.");
}
