use std::fmt::{self};

use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};

#[derive(PartialEq, Debug, Clone, Copy, Eq)]
pub enum PingExtensionType {
    Capabilities,
    BasicRadius,
    HistoryRadius,
    Error,
    NonSupportedExtension(u16),
}

impl From<u16> for PingExtensionType {
    fn from(value: u16) -> Self {
        match value {
            0 => PingExtensionType::Capabilities,
            1 => PingExtensionType::BasicRadius,
            2 => PingExtensionType::HistoryRadius,
            65535 => PingExtensionType::Error,
            n => PingExtensionType::NonSupportedExtension(n),
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
            PingExtensionType::NonSupportedExtension(n) => n,
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
            PingExtensionType::NonSupportedExtension(n) => {
                write!(f, "NonSupportedExtension({n})")
            }
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

    fn ssz_fixed_len() -> usize {
        2
    }
}

impl Decode for PingExtensionType {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let value = u16::from_ssz_bytes(bytes)?;
        Ok(PingExtensionType::from(value))
    }

    fn ssz_fixed_len() -> usize {
        2
    }
}

impl Serialize for PingExtensionType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        u16::from(*self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PingExtensionType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        u16::deserialize(deserializer).map(PingExtensionType::from)
    }
}
