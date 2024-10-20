use alloy::primitives::{Bytes, U256};
use serde::{Deserialize, Serialize};
use ssz_types::{typenum, BitList};

use crate::{types::enr::Enr, OverlayContentKey};

use super::query_trace::QueryTrace;

/// The SSZ encoded representation of content key.
///
/// This is an alias for [alloy::primitives::Bytes] type, which is a wrapper around [bytes::Bytes].
///
/// While `Vec<u8>` is the most common way to represent the byte array, its usage as raw content
/// key is discouraged in favor of this type, for following reasons:
///
/// - The [bytes::Bytes] is cheaply cloneable and sliceable chunk of contiguous memory
///   - This makes it more suitable when cloning/coping is frequent, and modification is not
/// - The [alloy::primitives::Bytes] is a wrapper around `bytes::Bytes` that implements frequently
///   used traits (e.g. [ssz::Encode], [ssz::Decode], [std::fmt::Display], [std::str::FromStr]) and
///   supports (de)serialization to/from hex strings (with or without "0x" prefix).
///
/// Lack of support in third-party libraries is the most common issue with using this type. To work
/// around it, one can do any of the following:
///
/// - Wrap `RawContentKey` in a new type, and implement thirt-party trait that adds support
/// - Use `RawContentKey::to_vec` and `RawContentKey::from` to convert to/from `Vec<u8>`
pub type RawContentKey = Bytes;

/// The SSZ encoded representation of content value.
///
/// This is an alias for [alloy::primitives::Bytes] type, which is a wrapper around [bytes::Bytes].
///
/// While `Vec<u8>` is the most common way to represent the byte array, its usage as raw content
/// value is discouraged in favor of this type, for following reasons:
///
/// - The [bytes::Bytes] is cheaply cloneable and sliceable chunk of contiguous memory
///   - This makes it more suitable when cloning/coping is frequent, and modification is not
/// - The [alloy::primitives::Bytes] is a wrapper around `bytes::Bytes` that implements frequently
///   used traits (e.g. [ssz::Encode], [ssz::Decode], [std::fmt::Display], [std::str::FromStr]) and
///   supports (de)serialization to/from hex strings (with or without "0x" prefix).
///
/// Lack of support in third-party libraries is the most common issue with using this type. To work
/// around it, one can do any of the following:
///
/// - Wrap `RawContentValue` in a new type, and implement thirt-party trait that adds support
/// - Use `RawContentValue::to_vec` and `RawContentValue::from` to convert to/from `Vec<u8>`
pub type RawContentValue = Bytes;

pub type DataRadius = U256;
pub type Distance = U256;

/// Response for Ping endpoint
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PongInfo {
    pub enr_seq: u64,
    pub data_radius: DataRadius,
}

pub type FindNodesInfo = Vec<Enr>;

pub const MAX_CONTENT_KEYS_PER_OFFER: usize = 64;

/// Response for Offer endpoint
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptInfo {
    pub content_keys: BitList<typenum::U64>,
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

/// Response for the FindContent endpoint
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FindContentInfo {
    #[serde(rename_all = "camelCase")]
    Content {
        content: RawContentValue,
        utp_transfer: bool,
    },
    #[serde(rename_all = "camelCase")]
    Enrs { enrs: Vec<Enr> },
}

/// Response for the GetContent endpoint
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetContentInfo {
    pub content: RawContentValue,
    pub utp_transfer: bool,
}

/// Parsed response for TraceGetContent endpoint
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
