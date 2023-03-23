use crate::execution::accumulator::EpochAccumulator;
use crate::execution::block_body::BlockBody;
use crate::execution::header::HeaderWithProof;
use crate::execution::receipts::Receipts;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::{Decode, Encode};
use trin_utils::bytes::{hex_decode, hex_encode};

/// An encodable portal network content value.
pub trait ContentValue: Sized {
    /// Encodes the content value into a byte vector.
    fn encode(&self) -> Vec<u8>;
    /// Decodes `buf` into a content value.
    fn decode(buf: &[u8]) -> anyhow::Result<Self>;
}

/// The length of the Merkle proof for the inclusion of a block header in a particular epoch
/// accumulator.
pub const EPOCH_ACC_PROOF_LEN: usize = 15;

/// A Portal History content value.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum HistoryContentValue {
    BlockHeaderWithProof(HeaderWithProof),
    BlockBody(BlockBody),
    Receipts(Receipts),
    EpochAccumulator(EpochAccumulator),
    /// A placeholder for data that could not be interpreted as any of the valid content types.
    Unknown(String),
}

impl ContentValue for HistoryContentValue {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::BlockHeaderWithProof(value) => value.as_ssz_bytes(),
            Self::BlockBody(value) => value.as_ssz_bytes(),
            Self::Receipts(value) => value.as_ssz_bytes(),
            Self::EpochAccumulator(value) => value.as_ssz_bytes(),
            Self::Unknown(value) => hex_decode(value).unwrap_or_default(),
        }
    }

    fn decode(buf: &[u8]) -> anyhow::Result<Self> {
        if let Ok(value) = HeaderWithProof::from_ssz_bytes(buf) {
            return Ok(Self::BlockHeaderWithProof(value));
        }

        if let Ok(value) = BlockBody::from_ssz_bytes(buf) {
            return Ok(Self::BlockBody(value));
        }

        if let Ok(value) = Receipts::from_ssz_bytes(buf) {
            return Ok(Self::Receipts(value));
        }

        if let Ok(value) = EpochAccumulator::from_ssz_bytes(buf) {
            return Ok(Self::EpochAccumulator(value));
        }

        Ok(Self::Unknown(hex_encode(buf)))
    }
}

impl Serialize for HistoryContentValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = match self {
            Self::BlockHeaderWithProof(value) => value.as_ssz_bytes(),
            Self::BlockBody(value) => value.as_ssz_bytes(),
            Self::Receipts(value) => value.as_ssz_bytes(),
            Self::EpochAccumulator(value) => value.as_ssz_bytes(),
            Self::Unknown(value) => {
                if value.is_empty() {
                    return serializer.serialize_str("0x0");
                }
                value.clone().into_bytes()
            }
        };
        serializer.serialize_str(&hex_encode(encoded))
    }
}

impl<'de> Deserialize<'de> for HistoryContentValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        if s.as_str() == "0x0" {
            return Ok(Self::Unknown(String::from("")));
        }
        let content_bytes = hex_decode(&s).map_err(serde::de::Error::custom)?;

        if let Ok(value) = HeaderWithProof::from_ssz_bytes(&content_bytes) {
            return Ok(Self::BlockHeaderWithProof(value));
        }

        if let Ok(value) = BlockBody::from_ssz_bytes(&content_bytes) {
            return Ok(Self::BlockBody(value));
        }

        if let Ok(value) = Receipts::from_ssz_bytes(&content_bytes) {
            return Ok(Self::Receipts(value));
        }

        if let Ok(value) = EpochAccumulator::from_ssz_bytes(&content_bytes) {
            return Ok(Self::EpochAccumulator(value));
        }

        Ok(Self::Unknown(s))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use serde_json::Value;

    use std::fs;

    /// Max number of blocks / epoch = 2 ** 13
    pub const EPOCH_SIZE: usize = 8192;

    #[test]
    fn header_with_proof_encode_decode_fluffy() {
        let file =
            fs::read_to_string("../trin-validation/src/assets/fluffy/header_with_proofs.json")
                .unwrap();
        let json: Value = serde_json::from_str(&file).unwrap();
        let json = json.as_object().unwrap();
        for (block_num, obj) in json {
            let block_num: u64 = block_num.parse().unwrap();
            let header_with_proof = obj.get("value").unwrap().as_str().unwrap();
            let header_with_proof_encoded = hex_decode(header_with_proof).unwrap();
            let header_with_proof =
                HeaderWithProof::from_ssz_bytes(&header_with_proof_encoded).unwrap();

            assert_eq!(header_with_proof.header.number, block_num);

            let encoded = header_with_proof.as_ssz_bytes();
            assert_eq!(encoded, header_with_proof_encoded);
        }
    }

    #[test]
    fn ssz_serde_encode_decode_fluffy_epoch_accumulator() {
        // values sourced from: https://github.com/status-im/portal-spec-tests
        let epoch_acc_ssz = fs::read("../trin-validation/src/assets/fluffy/epoch_acc.bin").unwrap();
        let epoch_acc = EpochAccumulator::from_ssz_bytes(&epoch_acc_ssz).unwrap();
        assert_eq!(epoch_acc.len(), EPOCH_SIZE);
        assert_eq!(epoch_acc.as_ssz_bytes(), epoch_acc_ssz);
    }
}
