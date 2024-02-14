//! # ethportal-api
//!
//! `ethportal_api` is a collection of Portal Network APIs and types.
#![warn(clippy::unwrap_used)]
#![warn(clippy::uninlined_format_args)]

#[macro_use]
extern crate lazy_static;

mod beacon;
mod dashboard;
pub mod discv5;
mod eth;
mod history;
pub mod state;
#[cfg(test)]
mod test_utils;
pub mod types;
pub mod utils;
mod web3;

pub use crate::discv5::{Discv5ApiClient, Discv5ApiServer};
pub use beacon::{BeaconNetworkApiClient, BeaconNetworkApiServer};
pub use eth::{EthApiClient, EthApiServer};
pub use history::{HistoryNetworkApiClient, HistoryNetworkApiServer};
pub use state::{StateNetworkApiClient, StateNetworkApiServer};
pub use web3::{Web3ApiClient, Web3ApiServer};

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

pub use types::{
    consensus,
    consensus::light_client,
    content_value::{
        beacon::BeaconContentValue, error::ContentValueError, history::HistoryContentValue,
        state::StateContentValue,
    },
    execution::{block_body::*, header::*, receipts::*},
};

// Re-exports jsonrpsee crate
pub use jsonrpsee;
pub use types::content_value::ContentValue;

pub use types::{discv5::*, enr::*, node_id::*};
