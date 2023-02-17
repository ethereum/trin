//! # ethportal-api
//!
//! `ethportal_api` is a collection of Portal Network APIs and types.

mod discv5;
mod history;
pub mod types;
mod web3;

#[cfg(feature = "client")]
pub use discv5::Discv5ApiClient;

#[cfg(feature = "server")]
pub use discv5::Discv5ApiServer;

#[cfg(feature = "client")]
pub use history::HistoryNetworkApiClient;

#[cfg(feature = "server")]
pub use history::HistoryNetworkApiServer;

#[cfg(feature = "client")]
pub use web3::Web3ApiClient;

#[cfg(feature = "server")]
pub use web3::Web3ApiServer;

pub use types::{
    content_item::{
        BlockBody, ContentItem, EpochAccumulator, HeaderRecord, HeaderWithProof, HistoryContentItem,
    },
    content_key::HistoryContentKey,
};

// Re-exports jsonrpsee crate
pub use jsonrpsee;

pub use reth_primitives::{Header, Receipt, TransactionSigned};
