//! # ethportal-api
//!
//! `ethportal_api` is a collection of Portal Network APIs and types.
#![warn(clippy::unwrap_used)]

mod discv5;
mod history;
pub mod types;
mod web3;

pub use crate::discv5::{Discv5ApiClient, Discv5ApiServer};
pub use history::{HistoryNetworkApiClient, HistoryNetworkApiServer};
pub use web3::{Web3ApiClient, Web3ApiServer};

// Re-exports trin-types
pub use trin_types::content_key::{
    BlockBodyKey, BlockHeaderKey, BlockReceiptsKey, EpochAccumulatorKey, HistoryContentKey,
    OverlayContentKey, StateContentKey,
};
pub use trin_types::content_value::{
    ContentValue, ContentValueError, HistoryContentValue, PossibleHistoryContentValue,
};
pub use trin_types::execution::block_body::*;
pub use trin_types::execution::header::*;
pub use trin_types::execution::receipts::*;

// Re-exports jsonrpsee crate
pub use jsonrpsee;
