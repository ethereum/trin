#![warn(clippy::unwrap_used)]

#[macro_use]
extern crate lazy_static;

pub mod discovery;
pub mod events;
pub mod find;
pub mod metrics;
pub mod overlay;
mod overlay_service;
pub mod socket;
pub mod storage;
pub mod types;
pub mod utils;
