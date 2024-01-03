use super::query_trace::QueryTrace;
use crate::{types::enr::Enr, BeaconContentKey, PossibleBeaconContentValue};
use serde::{Deserialize, Serialize};

/// Response for FindContent & RecursiveFindContent endpoints
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum ContentInfo {
    #[serde(rename_all = "camelCase")]
    ConnectionId { connection_id: u16 },
    #[serde(rename_all = "camelCase")]
    Content {
        content: PossibleBeaconContentValue,
        utp_transfer: bool,
    },
    #[serde(rename_all = "camelCase")]
    Enrs { enrs: Vec<Enr> },
}

/// Parsed response for TraceRecursiveFindContent endpoint
///
/// The RPC response encodes absent content as "0x". This struct
/// represents the content info, using None for absent content.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceContentInfo {
    pub content: PossibleBeaconContentValue,
    pub utp_transfer: bool,
    pub trace: QueryTrace,
}

/// Response for PaginateLocalContentKeys endpoint
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginateLocalContentInfo {
    pub content_keys: Vec<BeaconContentKey>,
    pub total_entries: u64,
}
