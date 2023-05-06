//! # ethportal-api
//!
//! `ethportal_api` is a collection of Portal Network APIs and types.
#![warn(clippy::unwrap_used)]

#[macro_use]
extern crate lazy_static;

mod beacon;
pub mod discv5;
mod history;
pub mod trin_types;
pub mod types;
mod web3;

pub use crate::discv5::{Discv5ApiClient, Discv5ApiServer};
pub use beacon::{BeaconNetworkApiClient, BeaconNetworkApiServer};
pub use history::{HistoryNetworkApiClient, HistoryNetworkApiServer};
pub use web3::{Web3ApiClient, Web3ApiServer};

// Re-exports trin-types
pub use trin_types::content_key::{
    BeaconContentKey, BlockBodyKey, BlockHeaderKey, BlockReceiptsKey, EpochAccumulatorKey,
    HistoryContentKey, LightClientBootstrapKey, LightClientUpdatesKey, OverlayContentKey,
    StateContentKey,
};
pub use trin_types::content_value::{
    BeaconContentValue, ContentValue, ContentValueError, HistoryContentValue,
    PossibleBeaconContentValue, PossibleHistoryContentValue,
};
pub use trin_types::execution::block_body::*;
pub use trin_types::execution::header::*;
pub use trin_types::execution::receipts::*;

// Re-exports jsonrpsee crate
pub use jsonrpsee;

pub use trin_types::discv5::*;
pub use trin_types::enr::*;
pub use trin_types::node_id::*;
