//! # ethportal-api
//!
//! `ethportal_api` is a collection of Portal Network APIs and types.
#![warn(clippy::unwrap_used)]

mod discv5;
mod history;
pub mod types;
mod web3;

pub use discv5::{Discv5ApiClient, Discv5ApiServer};
pub use history::{HistoryNetworkApiClient, HistoryNetworkApiServer};
pub use types::{
    content_item::{
        BlockBody, ContentItem, EpochAccumulator, HeaderRecord, HeaderWithProof, HistoryContentItem,
    },
    content_key::HistoryContentKey,
};
pub use web3::{Web3ApiClient, Web3ApiServer};

// Re-exports jsonrpsee crate
pub use jsonrpsee;

pub use reth_primitives::{Header, Receipt, TransactionSigned};
