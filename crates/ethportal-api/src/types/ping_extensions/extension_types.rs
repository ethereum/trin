use std::fmt::{self};

use ssz::{Decode, Encode};

#[derive(PartialEq, Debug, Clone, Copy, Eq)]
pub enum PingExtensionType {
    Capabilities,
    BasicRadius,
    HistoryRadius,
    Error,
}

impl TryFrom<u16> for PingExtensionType {
    type Error = ExtensionError;

    fn try_from(value: u16) -> Result<Self, ExtensionError> {
        match value {
            0 => Ok(PingExtensionType::Capabilities),
            1 => Ok(PingExtensionType::BasicRadius),
            2 => Ok(PingExtensionType::HistoryRadius),
            65535 => Ok(PingExtensionType::Error),
            _ => Err(ExtensionError::NonSupportedExtension(value)),
        }
    }
}

impl From<PingExtensionType> for u16 {
    fn from(value: PingExtensionType) -> u16 {
        match value {
            PingExtensionType::Capabilities => 0,
            PingExtensionType::BasicRadius => 1,
            PingExtensionType::HistoryRadius => 2,
            PingExtensionType::Error => 65535,
        }
    }
}

impl fmt::Display for PingExtensionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PingExtensionType::Capabilities => write!(f, "Capabilities"),
            PingExtensionType::BasicRadius => write!(f, "BasicRadius"),
            PingExtensionType::HistoryRadius => write!(f, "HistoryRadius"),
            PingExtensionType::Error => write!(f, "Error"),
        }
    }
}

impl Encode for PingExtensionType {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        u16::from(*self).ssz_append(buf);
    }

    fn ssz_bytes_len(&self) -> usize {
        2
    }
}

impl Decode for PingExtensionType {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let value = u16::from_ssz_bytes(bytes)?;
        PingExtensionType::try_from(value).map_err(|_| ssz::DecodeError::NoMatchingVariant)
    }
}

#[derive(Debug)]
pub enum ExtensionError {
    NonSupportedExtension(u16),
}
