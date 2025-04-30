#![warn(clippy::unwrap_used)]
#![warn(clippy::uninlined_format_args)]

pub mod cli;
pub mod handle;
pub mod run;

pub use run::{run_trin, run_trin_from_trin_config, run_trin_with_rpc};
