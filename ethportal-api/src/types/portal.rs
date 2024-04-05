use alloy_primitives::U256;
use serde::{Deserialize, Serialize};
use ssz_types::{typenum, BitList};

use crate::types::enr::Enr;

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
