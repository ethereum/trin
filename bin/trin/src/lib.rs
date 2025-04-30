#![warn(clippy::unwrap_used)]
#![warn(clippy::uninlined_format_args)]

mod cli;
mod handle;
mod run;

pub use cli::TrinConfig;
pub use handle::{SubnetworkOverlays, TrinHandle};
pub use run::{run_trin, run_trin_from_trin_config, run_trin_with_rpc, NodeRuntimeConfig};
