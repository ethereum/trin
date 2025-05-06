use std::{
    fmt,
    fmt::{Display, Formatter},
    str::FromStr,
};

use thiserror::Error;

use crate::utils::bytes::hex_encode;

/// Error thrown when failed to parse a valid [`ForkName`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("Unknown fork for digest: {0}")]
pub struct ParseForkNameError(String);

pub const FORK_DIGEST_LEN: usize = 4;
pub type ForkDigest = [u8; FORK_DIGEST_LEN];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ForkName {
    Bellatrix,
    Capella,
    Deneb,
    Electra,
}

impl TryFrom<ForkDigest> for ForkName {
    type Error = ParseForkNameError;

    fn try_from(fork_digest: ForkDigest) -> Result<Self, Self::Error> {
        match fork_digest {
            [0x4a, 0x26, 0xc5, 0x8b] => Ok(ForkName::Bellatrix),
            [0xbb, 0xa4, 0xda, 0x96] => Ok(ForkName::Capella),
            [0x6a, 0x95, 0xa1, 0xa9] => Ok(ForkName::Deneb),
            [0xad, 0x53, 0x2c, 0xeb] => Ok(ForkName::Electra),
            _ => Err(ParseForkNameError(hex_encode(fork_digest))),
        }
    }
}

impl ForkName {
    pub fn as_fork_digest(&self) -> [u8; 4] {
        match self {
            ForkName::Bellatrix => [0x4a, 0x26, 0xc5, 0x8b],
            ForkName::Capella => [0xbb, 0xa4, 0xda, 0x96],
            ForkName::Deneb => [0x6a, 0x95, 0xa1, 0xa9],
            ForkName::Electra => [0xad, 0x53, 0x2c, 0xeb],
        }
    }

    pub fn as_capitalized_str(&self) -> &'static str {
        match self {
            ForkName::Bellatrix => "Bellatrix",
            ForkName::Capella => "Capella",
            ForkName::Deneb => "Deneb",
            ForkName::Electra => "Electra",
        }
    }
}

impl FromStr for ForkName {
    type Err = String;

    fn from_str(fork_name: &str) -> Result<Self, String> {
        Ok(match fork_name.to_lowercase().as_ref() {
            "bellatrix" | "merge" => ForkName::Bellatrix,
            "capella" => ForkName::Capella,
            "deneb" => ForkName::Deneb,
            "electra" => ForkName::Electra,
            _ => return Err(format!("unknown fork name: {fork_name}")),
        })
    }
}

impl Display for ForkName {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            ForkName::Bellatrix => "bellatrix".fmt(f),
            ForkName::Capella => "capella".fmt(f),
            ForkName::Deneb => "deneb".fmt(f),
            ForkName::Electra => "electra".fmt(f),
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

    #[rstest::rstest]
    fn to_and_from_digest(
        #[values(
            ForkName::Bellatrix,
            ForkName::Capella,
            ForkName::Deneb,
            ForkName::Electra
        )]
        fork_name: ForkName,
    ) {
        let digest = fork_name.as_fork_digest();
        assert_eq!(ForkName::try_from(digest), Ok(fork_name))
    }

    #[test]
    fn to_and_from_string() {
        assert_eq!(ForkName::from_str("bellatrix"), Ok(ForkName::Bellatrix));
        assert_eq!(ForkName::from_str("capella"), Ok(ForkName::Capella));
        assert_eq!(ForkName::from_str("deneb"), Ok(ForkName::Deneb));
        assert_eq!(ForkName::from_str("electra"), Ok(ForkName::Electra));
        assert_eq!(ForkName::Bellatrix.to_string(), "bellatrix");
        assert_eq!(ForkName::Capella.to_string(), "capella");
        assert_eq!(ForkName::Deneb.to_string(), "deneb");
        assert_eq!(ForkName::Electra.to_string(), "electra");
    }
}
