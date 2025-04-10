use std::ops::{Deref, DerefMut};

use alloy::primitives::Bytes;
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_types::{typenum, BitList, VariableList};

use super::protocol_versions::ProtocolVersion;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct AcceptCodeList(VariableList<AcceptCode, typenum::U64>);

impl AcceptCodeList {
    /// Creates a new AcceptCodeList with the specified capacity, initialized to
    /// `AcceptCode::Declined`
    ///
    /// Errors if the capacity is greater than `64`.
    pub fn new(capacity: usize) -> Result<Self, ssz_types::Error> {
        VariableList::new(vec![AcceptCode::Declined; capacity]).map(Self)
    }

    /// Sets an accept_code at position `index` within the accept code list
    ///
    /// # Panics
    ///
    /// Panics if `index > len`.
    pub fn set(&mut self, index: usize, value: AcceptCode) {
        let len = self.len();
        if let Some(accept_code) = self.0.get_mut(index) {
            *accept_code = value;
        } else {
            panic!("Index out of bounds: index {index} is greater than len {len}");
        }
    }

    /// Returns true if all accept codes are `AcceptCode::Accepted`
    pub fn all_declined(&self) -> bool {
        !self.contains(&AcceptCode::Accepted)
    }

    pub fn encode(&self, protocol_version: ProtocolVersion) -> Result<Bytes, AcceptCodeListError> {
        if protocol_version.is_v1_enabled() {
            Ok(Bytes::from(self.0.as_ssz_bytes()))
        } else {
            let mut v0_content_keys = BitList::<typenum::U64>::with_capacity(self.0.len())?;
            for (index, accept_code) in self.0.iter().enumerate() {
                v0_content_keys.set(index, accept_code == &AcceptCode::Accepted)?;
            }
            Ok(Bytes::from(v0_content_keys.as_ssz_bytes()))
        }
    }

    pub fn decode(
        protocol_version: ProtocolVersion,
        raw_content_keys: Bytes,
    ) -> Result<AcceptCodeList, AcceptCodeListError> {
        if protocol_version.is_v1_enabled() {
            Ok(AcceptCodeList(
                VariableList::<AcceptCode, typenum::U64>::from_ssz_bytes(&raw_content_keys)?,
            ))
        } else {
            let v0_content_keys = BitList::<typenum::U64>::from_ssz_bytes(&raw_content_keys)?;
            let mut accept_code_list = AcceptCodeList::new(v0_content_keys.len())?;
            for (index, bit) in v0_content_keys.iter().enumerate() {
                let accept_code = if bit {
                    AcceptCode::Accepted
                } else {
                    AcceptCode::Declined
                };
                accept_code_list.set(index, accept_code);
            }
            Ok(accept_code_list)
        }
    }
}

impl Deref for AcceptCodeList {
    type Target = [AcceptCode];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AcceptCodeList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub mod accept_code_hex {
    use serde::{Deserializer, Serializer};

    use super::*;

    pub fn serialize<S>(accept_code_list: &AcceptCodeList, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = accept_code_list
            .encode(ProtocolVersion::V1)
            .map_err(serde::ser::Error::custom)?;
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<AcceptCodeList, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Bytes::deserialize(deserializer)?;
        AcceptCodeList::decode(ProtocolVersion::V1, bytes).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AcceptCodeListError {
    #[error("Failed to decode accept code list (SSZ): {0}")]
    DecodeError(String),

    #[error("SSZ types error: {0}")]
    SSZTypesError(String),
}

impl From<ssz::DecodeError> for AcceptCodeListError {
    fn from(err: ssz::DecodeError) -> Self {
        AcceptCodeListError::DecodeError(format!("{err:?}"))
    }
}

impl From<ssz_types::Error> for AcceptCodeListError {
    fn from(err: ssz_types::Error) -> Self {
        AcceptCodeListError::SSZTypesError(format!("{err:?}"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptCode {
    /// The content was accepted
    Accepted,
    /// Generic decline, catch all if their is no specified case
    Declined,
    /// Declined, content already stored
    AlreadyStored,
    /// Declined, content not within node's radius
    NotWithinRadius,
    /// Declined, rate limit reached. Node can't handle anymore connections
    RateLimited,
    /// Declined, inbound rate limit reached for accepting a specific content_id, used to protect
    /// against thundering herds
    InboundTransferInProgress,
    /// Unspecified accept code, this should not be used
    Unspecified,
}

impl From<AcceptCode> for u8 {
    fn from(code: AcceptCode) -> u8 {
        match code {
            AcceptCode::Accepted => 0,
            AcceptCode::Declined => 1,
            AcceptCode::AlreadyStored => 2,
            AcceptCode::NotWithinRadius => 3,
            AcceptCode::RateLimited => 4,
            AcceptCode::InboundTransferInProgress => 5,
            AcceptCode::Unspecified => 255,
        }
    }
}

impl From<u8> for AcceptCode {
    fn from(byte: u8) -> AcceptCode {
        match byte {
            0 => AcceptCode::Accepted,
            1 => AcceptCode::Declined,
            2 => AcceptCode::AlreadyStored,
            3 => AcceptCode::NotWithinRadius,
            4 => AcceptCode::RateLimited,
            5 => AcceptCode::InboundTransferInProgress,
            _ => AcceptCode::Unspecified,
        }
    }
}

impl Serialize for AcceptCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        u8::from(*self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AcceptCode {
    fn deserialize<D>(deserializer: D) -> Result<AcceptCode, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        u8::deserialize(deserializer).map(AcceptCode::from)
    }
}

impl Encode for AcceptCode {
    fn is_ssz_fixed_len() -> bool {
        <u8 as Encode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <u8 as Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        <u8 as Encode>::ssz_bytes_len(&u8::from(*self))
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        <u8 as Encode>::ssz_append(&u8::from(*self), buf)
    }
}

impl Decode for AcceptCode {
    fn is_ssz_fixed_len() -> bool {
        <u8 as Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <u8 as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        u8::from_ssz_bytes(bytes).map(AcceptCode::from)
    }
}
