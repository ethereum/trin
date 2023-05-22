//! # ethportal-api
//!
//! `ethportal_api` is a collection of Portal Network APIs and types.
#![warn(clippy::unwrap_used)]

#[macro_use]
extern crate lazy_static;

mod beacon;
mod dashboard;
pub mod discv5;
mod history;
pub mod types;
pub mod utils;
mod web3;

pub use crate::discv5::{Discv5ApiClient, Discv5ApiServer};
pub use beacon::{BeaconNetworkApiClient, BeaconNetworkApiServer};
pub use history::{HistoryNetworkApiClient, HistoryNetworkApiServer};
pub use web3::{Web3ApiClient, Web3ApiServer};

// Re-exports trin-types
pub use types::content_key::{
    BeaconContentKey, BlockBodyKey, BlockHeaderKey, BlockReceiptsKey, EpochAccumulatorKey,
    HistoryContentKey, LightClientBootstrapKey, LightClientUpdatesKey, OverlayContentKey,
    StateContentKey,
};
pub use types::content_value::{
    BeaconContentValue, ContentValue, ContentValueError, HistoryContentValue,
    PossibleBeaconContentValue, PossibleHistoryContentValue,
};
pub use types::execution::block_body::*;
pub use types::execution::header::*;
pub use types::execution::receipts::*;

// Re-exports jsonrpsee crate
pub use jsonrpsee;

pub use types::discv5::*;
pub use types::enr::*;
pub use types::node_id::*;
