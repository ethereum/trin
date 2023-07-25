use crate::utils::bytes::hex_encode;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use thiserror::Error;

/// Error thrown when failed to parse a valid [`ForkName`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("Unknown fork name version: {0}")]
pub struct ParseForkNameError(String);

pub type ForkDigest = [u8; 4];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ForkName {
    Bellatrix,
    Capella,
}

impl TryFrom<ForkDigest> for ForkName {
    type Error = ParseForkNameError;

    fn try_from(fork_digest: ForkDigest) -> Result<Self, Self::Error> {
        match fork_digest {
            [0x0, 0x0, 0x0, 0x0] => Ok(ForkName::Bellatrix),
            [0xbb, 0xa4, 0xda, 0x96] => Ok(ForkName::Capella),
            _ => Err(ParseForkNameError(hex_encode(fork_digest))),
        }
    }
}

impl ForkName {
    pub fn as_fork_digest(&self) -> [u8; 4] {
        match self {
            ForkName::Bellatrix => [0x0, 0x0, 0x0, 0x0],
            ForkName::Capella => [0xbb, 0xa4, 0xda, 0x96],
        }
    }
}

impl FromStr for ForkName {
    type Err = String;

    fn from_str(fork_name: &str) -> Result<Self, String> {
        Ok(match fork_name.to_lowercase().as_ref() {
            "bellatrix" | "merge" => ForkName::Bellatrix,
            "capella" => ForkName::Capella,
            _ => return Err(format!("unknown fork name: {}", fork_name)),
        })
    }
}

impl Display for ForkName {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            ForkName::Bellatrix => "bellatrix".fmt(f),
            ForkName::Capella => "capella".fmt(f),
        }
    }
}

impl From<ForkName> for String {
    fn from(fork: ForkName) -> String {
        fork.to_string()
    }
}

impl TryFrom<String> for ForkName {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::from_str(&s)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn fork_name_bellatrix_or_merge() {
        assert_eq!(ForkName::from_str("bellatrix"), Ok(ForkName::Bellatrix));
        assert_eq!(ForkName::from_str("capella"), Ok(ForkName::Capella));
        assert_eq!(ForkName::Bellatrix.to_string(), "bellatrix");
        assert_eq!(ForkName::Capella.to_string(), "capella");
    }
}
