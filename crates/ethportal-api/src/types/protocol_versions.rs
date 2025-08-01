use std::{cmp::Ordering, ops::Deref};

use alloy::primitives::Bytes;
use alloy_rlp::{Decodable, Encodable};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum::U8, VariableList};

pub const ENR_PROTOCOL_VERSION_KEY: &str = "pv";

/// Portal Protocol Versions
///
/// https://github.com/ethereum/portal-network-specs/blob/master/protocol-version-changelog.md
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolVersion {
    /// The initial version of the protocol.
    V0,
    /// Adds `accept codes` and varint size encoding for find content messages.
    V1,
    /// Uses 'p' ENR key to indicate protocol version and chain id.
    V2,
    /// Unspecified version is a version that we don't know about, but the other side does.
    UnspecifiedVersion(u8),
}

impl Deref for ProtocolVersion {
    type Target = u8;

    fn deref(&self) -> &Self::Target {
        match self {
            ProtocolVersion::V0 => &0,
            ProtocolVersion::V1 => &1,
            ProtocolVersion::V2 => &2,
            ProtocolVersion::UnspecifiedVersion(version) => version,
        }
    }
}

impl ProtocolVersion {
    pub fn is_v1_enabled(&self) -> bool {
        self >= &ProtocolVersion::V1
    }
}

impl From<ProtocolVersion> for u8 {
    fn from(version: ProtocolVersion) -> u8 {
        *version
    }
}

impl From<u8> for ProtocolVersion {
    fn from(version: u8) -> ProtocolVersion {
        match version {
            0 => ProtocolVersion::V0,
            1 => ProtocolVersion::V1,
            2 => ProtocolVersion::V2,
            version => ProtocolVersion::UnspecifiedVersion(version),
        }
    }
}

impl Encode for ProtocolVersion {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        u8::from(*self).ssz_append(buf);
    }

    fn ssz_bytes_len(&self) -> usize {
        1
    }

    fn ssz_fixed_len() -> usize {
        1
    }
}

impl Decode for ProtocolVersion {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let value = u8::from_ssz_bytes(bytes)?;
        Ok(ProtocolVersion::from(value))
    }

    fn ssz_fixed_len() -> usize {
        1
    }
}

impl PartialOrd for ProtocolVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ProtocolVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        u8::from(*self).cmp(&u8::from(*other))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[ssz(struct_behaviour = "transparent")]
pub struct ProtocolVersionList(pub VariableList<ProtocolVersion, U8>);

impl ProtocolVersionList {
    /// Panics if the length of the list is greater than 8.
    pub fn new(versions: Vec<ProtocolVersion>) -> Self {
        Self(VariableList::new(versions).expect("This function only accepts up to 8 elements"))
    }

    pub fn is_strictly_sorted_and_specified(&self) -> bool {
        for i in 0..self.len() {
            if let ProtocolVersion::UnspecifiedVersion(_) = self.0[i] {
                return false;
            }
            if i > 0 && self.0[i - 1] >= self.0[i] {
                return false;
            }
        }
        true
    }
}

impl Deref for ProtocolVersionList {
    type Target = [ProtocolVersion];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Encodable for ProtocolVersionList {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        let ssz_bytes = self.as_ssz_bytes();
        let bytes = Bytes::from(ssz_bytes);
        bytes.encode(out);
    }
}

impl Decodable for ProtocolVersionList {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let bytes = Bytes::decode(buf)?;
        let supported_versions = ProtocolVersionList::from_ssz_bytes(&bytes)
            .map_err(|_| alloy_rlp::Error::Custom("Failed to decode SSZ ProtocolVersionList"))?;
        Ok(supported_versions)
    }
}

#[derive(Debug)]
pub enum ProtocolVersionError {
    FailedToDecode,
    NoMatchingVersion,
}

#[cfg(test)]
mod test {
    use discv5::{enr::CombinedKey, Enr};

    use super::*;

    #[test]
    fn test_encode_decode_protocol_version_key() {
        let enr = {
            let mut builder = Enr::builder();

            builder.add_value(
                ENR_PROTOCOL_VERSION_KEY,
                &ProtocolVersionList::new(vec![ProtocolVersion::V0]),
            );

            builder.build(&CombinedKey::generate_secp256k1()).unwrap()
        };

        assert_eq!(
            enr.get_decodable::<ProtocolVersionList>(ENR_PROTOCOL_VERSION_KEY)
                .expect("Protocol Version key doesn't exist")
                .expect("Failed to decode Protocol Version value"),
            ProtocolVersionList::new(vec![ProtocolVersion::V0])
        );
    }
}
