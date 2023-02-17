pub mod cli;
pub mod jsonrpc;
pub mod locks;
pub mod portalnet;
pub mod socket;
pub mod types;
pub mod utils;

#[macro_use]
extern crate lazy_static;

pub const TRIN_VERSION: &str = env!("CARGO_PKG_VERSION");
