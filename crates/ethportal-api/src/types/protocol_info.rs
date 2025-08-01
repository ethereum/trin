use std::io::BufRead;

use alloy_rlp::{Decodable, Encodable};
use anyhow::ensure;

use crate::ProtocolVersion;

/// ENR key for Portal protocol info.
pub const ENR_PORTAL_KEY: &str = "p";

/// The information about active Portal Protocol.
///
/// Current implementation follows the protocol version 2, specified in
/// [Portal Wire Protocol spec](https://github.com/ethereum/portal-network-specs/blob/dd7b7cbae96a1c54546263d8484f1aa01c5035b9/portal-wire-protocol.md#enr-record).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolInfo {
    min_protocol_version: ProtocolVersion,
    max_protocol_version: ProtocolVersion,
    chain_id: u64,
}

impl ProtocolInfo {
    pub fn new(
        min_protocol_version: ProtocolVersion,
        max_protocol_version: ProtocolVersion,
        chain_id: u64,
    ) -> anyhow::Result<Self> {
        ensure!(
            min_protocol_version <= max_protocol_version,
            "Min version ({}) must be lower than Max version ({})",
            *min_protocol_version,
            *max_protocol_version,
        );
        Ok(Self {
            min_protocol_version,
            max_protocol_version,
            chain_id,
        })
    }

    pub fn min_protocol_version(&self) -> ProtocolVersion {
        self.min_protocol_version
    }

    pub fn max_protocol_version(&self) -> ProtocolVersion {
        self.max_protocol_version
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn supports(&self, protocol_version: ProtocolVersion) -> bool {
        (self.min_protocol_version..=self.max_protocol_version).contains(&protocol_version)
    }

    /// Returns the highest common protocol version, or `None` otherwise.
    ///
    /// It also returns `None` if other is not part of the same chain.
    pub fn highest_common_protocol_version(&self, other: &ProtocolInfo) -> Option<ProtocolVersion> {
        if self.chain_id != other.chain_id {
            return None;
        }

        let min = *self.min_protocol_version;
        let max = *self.max_protocol_version;
        (min..=max)
            .rev()
            .map(ProtocolVersion::from)
            .find(|protocol_version| other.supports(*protocol_version))
    }

    fn rlp_payload_length(&self) -> usize {
        Encodable::length(&*self.min_protocol_version)
            + Encodable::length(&*self.max_protocol_version)
            + Encodable::length(&self.chain_id)
    }
}

impl Encodable for ProtocolInfo {
    fn length(&self) -> usize {
        let payload_length = self.rlp_payload_length();
        payload_length + alloy_rlp::length_of_length(payload_length)
    }

    fn encode(&self, out: &mut dyn bytes::BufMut) {
        alloy_rlp::Header {
            list: true,
            payload_length: self.rlp_payload_length(),
        }
        .encode(out);
        self.min_protocol_version.encode(out);
        self.max_protocol_version.encode(out);
        self.chain_id.encode(out);
    }
}

impl Decodable for ProtocolInfo {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let alloy_rlp::Header {
            list,
            payload_length,
        } = alloy_rlp::Header::decode(buf)?;

        if !list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let started_len = buf.len();
        if started_len < payload_length {
            return Err(alloy_rlp::Error::InputTooShort);
        }
        let min_protocol_version: u8 = Decodable::decode(buf)?;
        let max_protocol_version: u8 = Decodable::decode(buf)?;
        let chain_id = Decodable::decode(buf)?;

        let consumed = started_len - buf.len();

        if consumed > payload_length {
            // We shouldn't have consumed more than 'payload_length'
            return Err(alloy_rlp::Error::ListLengthMismatch {
                expected: payload_length,
                got: consumed,
            });
        }
        if payload_length > consumed {
            // Payload can be longer then consumed when peer upgraded the protocol version and
            // added more fields but we didn't.
            // In that case, we just read and ignore the rest of the payload.
            buf.consume(payload_length - consumed);
        }

        Self::new(
            min_protocol_version.into(),
            max_protocol_version.into(),
            chain_id,
        )
        .map_err(|_| alloy_rlp::Error::Custom("Decoded ProtocolInfo is invalid"))
    }
}

#[cfg(test)]
mod tests {
    use alloy::{
        hex::FromHex,
        primitives::{bytes, Bytes},
    };
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::only_v2("0xc3020201", ProtocolVersion::V2, ProtocolVersion::V2, 1)]
    #[case::v0_to_v2("0xc3800201", ProtocolVersion::V0, ProtocolVersion::V2, 1)]
    #[case::hoodi("0xc6020283088bb0", ProtocolVersion::V2, ProtocolVersion::V2, /* hoodi testnet */ 560048)]
    fn encode_decode(
        #[case] bytes: String,
        #[case] min_protocol_version: ProtocolVersion,
        #[case] max_protocol_version: ProtocolVersion,
        #[case] chain_id: u64,
    ) {
        let bytes = Bytes::from_hex(bytes).unwrap();
        let protocol_info =
            ProtocolInfo::new(min_protocol_version, max_protocol_version, chain_id).unwrap();

        assert_eq!(alloy_rlp::encode(protocol_info), bytes.to_vec());

        assert_eq!(
            alloy_rlp::decode_exact::<ProtocolInfo>(bytes),
            Ok(protocol_info),
        );
    }

    /// Tests that decoding rlp bytes that includes unknown version (e.g. 3) and extra bytes works.
    #[test]
    fn unsupported_protocol() {
        let bytes = bytes!("0xc602030182abcd");

        let expected_protocol_info = ProtocolInfo::new(
            ProtocolVersion::V2,
            ProtocolVersion::UnspecifiedVersion(3),
            1,
        )
        .unwrap();

        assert_eq!(
            alloy_rlp::decode_exact::<ProtocolInfo>(&bytes),
            Ok(expected_protocol_info)
        );
    }
}
