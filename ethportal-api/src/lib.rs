//! # ethportal-api
//!
//! `ethportal_api` is a collection of Portal Network APIs and types.

mod discv5;
mod history;
pub mod types;
mod web3;

pub use discv5::{Discv5ApiClient, Discv5ApiServer};
pub use history::{HistoryNetworkApiClient, HistoryNetworkApiServer};
pub use types::{
    accumulator::EpochAccumulator, block_body::BlockBody, block_header::BlockHeaderWithProof,
    content_item::HistoryContentItem, content_key::HistoryContentKey, receipts::BlockReceipts,
};
pub use web3::{Web3ApiClient, Web3ApiServer};

// Re-exports jsonrpsee crate
pub use jsonrpsee;
