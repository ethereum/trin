#![allow(clippy::all)]

use discv5::enr::CombinedKey;

pub mod discovery;
pub mod events;
pub mod metrics;
pub mod overlay;
mod overlay_service;
pub mod storage;
pub mod types;

pub type Enr = discv5::enr::Enr<CombinedKey>;
