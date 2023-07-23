use crate::types::content_key::HistoryContentKey;
use crate::types::content_value::{HistoryContentValue, PossibleHistoryContentValue};
use crate::types::enr::Enr;
use serde::{Deserialize, Serialize};
use ssz_types::{typenum, BitList};

use super::query_trace::QueryTrace;

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

/// Response for FindContent endpoint
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ContentInfo {
    #[serde(rename_all = "camelCase")]
    Content {
        content: HistoryContentValue,
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
    pub trace: QueryTrace,
}

/// Response for PaginateLocalContentKeys endpoint
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginateLocalContentInfo {
    pub content_keys: Vec<HistoryContentKey>,
    pub total_entries: u64,
}
