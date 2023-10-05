//! # ethportal-api
//!
//! `ethportal_api` is a collection of Portal Network APIs and types.
#![warn(clippy::unwrap_used)]

#[macro_use]
extern crate lazy_static;

mod beacon;
mod dashboard;
pub mod discv5;
mod eth;
mod history;
pub mod types;
pub mod utils;
mod web3;

pub use beacon::{BeaconNetworkApiClient, BeaconNetworkApiServer};
pub use eth::{EthApiClient, EthApiServer};
pub use history::{HistoryNetworkApiClient, HistoryNetworkApiServer};
// Re-exports jsonrpsee crate
pub use jsonrpsee;
pub use types::consensus;
pub use types::consensus::light_client;
pub use types::content_key::{
    beacon::{BeaconContentKey, LightClientBootstrapKey, LightClientUpdatesByRangeKey},
    error::ContentKeyError,
    history::{
        BlockBodyKey, BlockHeaderKey, BlockReceiptsKey, EpochAccumulatorKey, HistoryContentKey,
        RawContentKey,
    },
    overlay::{IdentityContentKey, OverlayContentKey},
    state::StateContentKey,
};
pub use types::content_value::ContentValue;
pub use types::content_value::{
    beacon::{BeaconContentValue, PossibleBeaconContentValue},
    error::ContentValueError,
    history::{HistoryContentValue, PossibleHistoryContentValue},
};
pub use types::discv5::*;
pub use types::enr::*;
pub use types::execution::block_body::*;
pub use types::execution::header::*;
pub use types::execution::receipts::*;
pub use types::node_id::*;
pub use web3::{Web3ApiClient, Web3ApiServer};

pub use crate::discv5::{Discv5ApiClient, Discv5ApiServer};
