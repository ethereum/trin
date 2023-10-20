use serde::{Deserialize, Serialize};
use ssz_types::{typenum, BitList};

use super::query_trace::QueryTrace;
use crate::types::enr::Enr;
use crate::HistoryContentKey;
use crate::PossibleHistoryContentValue;

pub type DataRadius = ethereum_types::U256;
pub type Distance = ethereum_types::U256;

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
    pub enr_seq: u32,
    pub data_radius: DataRadius,
}

pub type FindNodesInfo = Vec<Enr>;

/// Response for FindContent & RecursiveFindContent endpoints
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ContentInfo {
    #[serde(rename_all = "camelCase")]
    ConnectionId { connection_id: u16 },
    #[serde(rename_all = "camelCase")]
    Content {
        content: PossibleHistoryContentValue,
        utp_transfer: bool,
    },
    #[serde(rename_all = "camelCase")]
    Enrs { enrs: Vec<Enr> },
}

/// Response for Offer endpoint
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptInfo {
    pub content_keys: BitList<typenum::U8>,
}

/// Parsed response for TraceRecursiveFindContent endpoint
///
/// The RPC response encodes absent content as "0x". This struct
/// represents the content info, using None for absent content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceContentInfo {
    pub content: PossibleHistoryContentValue,
    pub utp_transfer: bool,
    pub trace: QueryTrace,
}

/// Response for PaginateLocalContentKeys endpoint
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginateLocalContentInfo {
    pub content_keys: Vec<HistoryContentKey>,
    pub total_entries: u64,
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
