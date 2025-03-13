use std::ops::Deref;

use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_types::{
    typenum::{self, UInt, UTerm, B0, B1},
    VariableList,
};

// 1100 in binary is 10001001100
pub type U1100 = UInt<
    UInt<
        UInt<
            UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B1>, B0>, B0>, B1>,
            B1,
        >,
        B0,
    >,
    B0,
>;

pub type ByteList32 = VariableList<u8, typenum::U32>;
pub type ByteList1024 = VariableList<u8, typenum::U1024>;
pub type ByteList1100 = VariableList<u8, U1100>;
pub type ByteList2048 = VariableList<u8, typenum::U2048>;
pub type ByteList32K = VariableList<u8, typenum::U32768>;
pub type ByteList1G = VariableList<u8, typenum::U1073741824>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct ByteList64(pub VariableList<u8, typenum::U64>);

impl ByteList64 {
    pub fn with_capacity(num_bytes: usize) -> Result<ByteList64, ssz_types::Error> {
        if num_bytes <= 64 {
            Ok(Self(VariableList::from(vec![0; num_bytes])))
        } else {
            Err(ssz_types::Error::OutOfBounds { i: 64, len: 64 })
        }
    }

    pub fn set(&mut self, i: usize, value: AcceptCode) -> Result<(), ssz_types::Error> {
        let len = self.len();

        if let Some(byte) = self.0.get_mut(i) {
            *byte = u8::from(value);
            Ok(())
        } else {
            Err(ssz_types::Error::OutOfBounds { i, len })
        }
    }

    pub fn get(&self, i: usize) -> Result<AcceptCode, ssz_types::Error> {
        let len = self.len();

        if let Some(byte) = self.0.get(i) {
            Ok(AcceptCode::from(*byte))
        } else {
            Err(ssz_types::Error::OutOfBounds { i, len })
        }
    }

    pub fn is_not_one(&self) -> bool {
        self.0.iter().all(|byte| *byte != 1)
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0.into()
    }
}

impl Deref for ByteList64 {
    type Target = VariableList<u8, typenum::U64>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Encode for ByteList64 {
    fn is_ssz_fixed_len() -> bool {
        <Vec<u8> as ssz::Encode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <Vec<u8> as ssz::Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        self.0.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.0.ssz_append(buf)
    }
}

impl Decode for ByteList64 {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let list = VariableList::from_ssz_bytes(bytes)?;
        Ok(Self(list))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcceptCode {
    /// Generic decline, send if there is no specific decline case
    Declined,
    /// The content was accepted
    Accepted,
    /// The content was already stored
    AlreadyStored,
    /// The content was rejected because the node is currently processing an inbound transfer for
    /// this content
    InboundTransferInProgress,
    /// The content was rejected because the node hit its rate limit
    RateLimited,
    /// The content was rejected because the content is not within the node's data radius
    NotWithinRadius,
    /// Unspecified accept code, this should not be used
    Unspecified,
}

impl From<AcceptCode> for u8 {
    fn from(code: AcceptCode) -> u8 {
        match code {
            AcceptCode::Declined => 0,
            AcceptCode::Accepted => 1,
            AcceptCode::AlreadyStored => 2,
            AcceptCode::InboundTransferInProgress => 3,
            AcceptCode::RateLimited => 4,
            AcceptCode::NotWithinRadius => 5,
            AcceptCode::Unspecified => 255,
        }
    }
}

impl From<u8> for AcceptCode {
    fn from(byte: u8) -> AcceptCode {
        match byte {
            0 => AcceptCode::Declined,
            1 => AcceptCode::Accepted,
            2 => AcceptCode::AlreadyStored,
            3 => AcceptCode::InboundTransferInProgress,
            4 => AcceptCode::RateLimited,
            5 => AcceptCode::NotWithinRadius,
            _ => AcceptCode::Unspecified,
        }
    }
}
