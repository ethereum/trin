use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::{
    typenum::{
        bit::{B0, B1},
        UInt, UTerm,
    },
    VariableList,
};

use crate::types::portal_wire::CustomPayload;

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

#[derive(PartialEq, Debug, Encode, Decode)]
pub struct CustomPayloadExtensionsFormat {
    pub r#type: u16,
    pub payload: VariableList<u8, U1100>,
}

impl TryFrom<CustomPayload> for CustomPayloadExtensionsFormat {
    type Error = anyhow::Error;

    fn try_from(value: CustomPayload) -> Result<Self, Self::Error> {
        CustomPayloadExtensionsFormat::from_ssz_bytes(&value.payload)
            .map_err(|e| anyhow::anyhow!("Failed to decode CustomPayloadExtensionsFormat: {:?}", e))
    }
}

#[derive(PartialEq, Debug, Clone, Copy, Eq)]
pub enum Extensions {
    Capabilities,
    BasicRadius,
    HistoryRadius,
    Error,
}

impl TryFrom<u16> for Extensions {
    type Error = ExtensionError;

    fn try_from(value: u16) -> Result<Self, ExtensionError> {
        match value {
            0 => Ok(Extensions::Capabilities),
            1 => Ok(Extensions::BasicRadius),
            2 => Ok(Extensions::HistoryRadius),
            65535 => Ok(Extensions::Error),
            _ => Err(ExtensionError::NonSupportedExtension(value)),
        }
    }
}

impl From<Extensions> for u16 {
    fn from(value: Extensions) -> u16 {
        match value {
            Extensions::Capabilities => 0,
            Extensions::BasicRadius => 1,
            Extensions::HistoryRadius => 2,
            Extensions::Error => 65535,
        }
    }
}

#[derive(Debug)]
pub enum ExtensionError {
    NonSupportedExtension(u16),
}
