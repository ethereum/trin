#![warn(clippy::unwrap_used)]
#![warn(clippy::uninlined_format_args)]

pub mod log;
pub mod submodules;
pub mod version;

shadow_rs::shadow!(build_info);
