#![warn(clippy::unwrap_used)]
#![warn(clippy::uninlined_format_args)]

pub mod accumulator;
pub mod constants;
pub mod header_validator;
pub mod historical_roots_acc;
pub mod merkle;
pub mod oracle;
pub mod validator;

use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "src/assets/"]
#[prefix = "validation_assets/"]
struct TrinValidationAssets;
