use std::ops::Deref;

use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, VariableList};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Encode, Decode)]
#[serde(transparent)]
#[ssz(struct_behaviour = "transparent")]
pub struct AcceptCodeList(pub VariableList<AcceptCode, typenum::U64>);

impl AcceptCodeList {
    pub fn with_capacity(num_bytes: usize) -> Result<Self, ssz_types::Error> {
        VariableList::new(vec![AcceptCode::Declined; num_bytes]).map(Self)
    }

    pub fn set(&mut self, index: usize, value: AcceptCode) -> Result<(), ssz_types::Error> {
        if let Some(accept_code) = self.0.get_mut(index) {
            *accept_code = value;
            Ok(())
        } else {
            Err(ssz_types::Error::OutOfBounds {
                i: index,
                len: self.len(),
            })
        }
    }

    pub fn get(&self, index: usize) -> Result<AcceptCode, ssz_types::Error> {
        if let Some(accept_code) = self.0.get(index) {
            Ok(*accept_code)
        } else {
            Err(ssz_types::Error::OutOfBounds {
                i: index,
                len: self.len(),
            })
        }
    }

    /// Returns true if all accept codes are `AcceptCode::Accepted`
    pub fn all_declined(&self) -> bool {
        self.0
            .iter()
            .all(|accept_code| *accept_code != AcceptCode::Accepted)
    }
}

impl Deref for AcceptCodeList {
    type Target = VariableList<AcceptCode, typenum::U64>;

    fn deref(&self) -> &Self::Target {
        &self.0
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
