use alloy_primitives::{Bytes, U256};
use serde::{Deserialize, Serialize};
use ssz_types::{typenum, BitList};

use crate::{types::enr::Enr, OverlayContentKey};

use super::query_trace::QueryTrace;

/// The SSZ encoded representation of content key.
pub type RawContentKey = Vec<u8>;
/// The SSZ encoded representation of content value.
pub type RawContentValue = Bytes;

pub type DataRadius = U256;
pub type Distance = U256;

/// Part of a TraceRecursiveFindContent response
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfo {
    pub enr: Enr,
    pub distance: Distance,
}

/// Response for Ping endpoint
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PongInfo {
    pub enr_seq: u64,
    pub data_radius: DataRadius,
}

pub type FindNodesInfo = Vec<Enr>;

/// Response for Offer endpoint
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptInfo {
    pub content_keys: BitList<typenum::U8>,
}

/// Response for TraceGossip endpoint
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceGossipInfo {
    // List of all ENRs that were offered the content
    pub offered: Vec<String>,
    // List of all ENRs that accepted the offer
    pub accepted: Vec<String>,
    // List of all ENRs to whom the content was successfully transferred
    pub transferred: Vec<String>,
}

/// Response for FindContent & RecursiveFindContent endpoints
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum ContentInfo {
    #[serde(rename_all = "camelCase")]
    ConnectionId { connection_id: u16 },
    #[serde(rename_all = "camelCase")]
    Content {
        content: RawContentValue,
        utp_transfer: bool,
    },
    #[serde(rename_all = "camelCase")]
    Enrs { enrs: Vec<Enr> },
}

/// Parsed response for TraceRecursiveFindContent endpoint
///
/// This struct represents the content info, and is only used
/// when the content is found locally or on the network.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceContentInfo {
    pub content: RawContentValue,
    pub utp_transfer: bool,
    pub trace: QueryTrace,
}

/// Response for PaginateLocalContentKeys endpoint
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginateLocalContentInfo<TContentKey: OverlayContentKey> {
    pub content_keys: Vec<TContentKey>,
    pub total_entries: u64,
}
