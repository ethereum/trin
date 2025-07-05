//! # ethportal-api
//!
//! `ethportal_api` is a collection of Portal Network APIs and types.
#![warn(clippy::unwrap_used)]
#![warn(clippy::uninlined_format_args)]

extern crate lazy_static;

mod beacon;
pub mod discv5;
mod eth;
mod history;
mod legacy_history;
mod state;
#[cfg(test)]
mod test_utils;
pub mod types;
pub mod utils;
pub mod version;
mod web3;

pub use beacon::{BeaconNetworkApiClient, BeaconNetworkApiServer};
pub use discv5::{Discv5ApiClient, Discv5ApiServer};
pub use eth::{EthApiClient, EthApiServer};
pub use history::{HistoryNetworkApiClient, HistoryNetworkApiServer};
// Re-exports jsonrpsee crate
pub use jsonrpsee;
pub use legacy_history::{LegacyHistoryNetworkApiClient, LegacyHistoryNetworkApiServer};
pub use state::{StateNetworkApiClient, StateNetworkApiServer};
pub use types::{
    consensus,
    consensus::light_client,
    content_key::{
        beacon::{BeaconContentKey, LightClientBootstrapKey, LightClientUpdatesByRangeKey},
        error::ContentKeyError,
        history::HistoryContentKey,
        legacy_history::LegacyHistoryContentKey,
        overlay::{IdentityContentKey, OverlayContentKey},
        state::StateContentKey,
    },
    content_value::{
        beacon::BeaconContentValue, error::ContentValueError, history::HistoryContentValue,
        legacy_history::LegacyHistoryContentValue, state::StateContentValue, ContentValue,
    },
    discv5::*,
    enr::*,
    execution::{block_body::*, receipts::*},
    node_id::*,
    portal::{RawContentKey, RawContentValue},
};
pub use web3::{Web3ApiClient, Web3ApiServer};
