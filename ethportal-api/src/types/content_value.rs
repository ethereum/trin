use crate::types::consensus::header_proof::HistoricalSummariesWithProof;
use crate::types::constants::CONTENT_ABSENT;
use crate::types::execution::accumulator::EpochAccumulator;
use crate::types::execution::block_body::BlockBody;
use crate::types::execution::header::HeaderWithProof;
use crate::types::execution::receipts::Receipts;
use crate::utils::bytes::{hex_decode, hex_encode};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::{Decode, Encode};
use thiserror::Error;

/// An encodable portal network content value.
pub trait ContentValue: Sized {
    /// Encodes the content value into a byte vector.
    fn encode(&self) -> Vec<u8>;
    /// Decodes `buf` into a content value.
    fn decode(buf: &[u8]) -> Result<Self, ContentValueError>;
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
}

/// A content response from the RPC server.
///
/// This type allows the RPC response to be non-error,
/// functioning as an Option, but with None serializing to "0x"
/// rather than 'null'.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PossibleHistoryContentValue {
    ContentPresent(HistoryContentValue),
    ContentAbsent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PossibleBeaconContentValue {
    ContentPresent(BeaconContentValue),
    ContentAbsent,
}

// impl Serialize for PossibleHistoryContentValue {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         match self {
//             PossibleHistoryContentValue::ContentPresent(content) => content.serialize(serializer),
//             PossibleHistoryContentValue::ContentAbsent => serializer.serialize_str(CONTENT_ABSENT),
//         }
//     }
// }
//
// impl<'de> Deserialize<'de> for PossibleHistoryContentValue {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         let s = String::deserialize(deserializer)?;
//
//         if s.as_str() == CONTENT_ABSENT {
//             return Ok(PossibleHistoryContentValue::ContentAbsent);
//         }
//
//         let content_bytes = hex_decode(&s).map_err(serde::de::Error::custom)?;
//
//         if let Ok(value) = HeaderWithProof::from_ssz_bytes(&content_bytes) {
//             return Ok(Self::ContentPresent(
//                 HistoryContentValue::BlockHeaderWithProof(value),
//             ));
//         }
//
//         if let Ok(value) = BlockBody::from_ssz_bytes(&content_bytes) {
//             return Ok(Self::ContentPresent(HistoryContentValue::BlockBody(value)));
//         }
//
//         if let Ok(value) = Receipts::from_ssz_bytes(&content_bytes) {
//             return Ok(Self::ContentPresent(HistoryContentValue::Receipts(value)));
//         }
//
//         if let Ok(value) = EpochAccumulator::from_ssz_bytes(&content_bytes) {
//             return Ok(Self::ContentPresent(HistoryContentValue::EpochAccumulator(
//                 value,
//             )));
//         }
//
//         Err(ContentValueError::UnknownContent {
//             bytes: s,
//             network: "history".to_string(),
//         })
//         .map_err(serde::de::Error::custom)
//     }
// }

impl Serialize for PossibleBeaconContentValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::ContentPresent(content) => content.serialize(serializer),
            Self::ContentAbsent => serializer.serialize_str(CONTENT_ABSENT),
        }
    }
}

impl<'de> Deserialize<'de> for PossibleBeaconContentValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        if s.as_str() == CONTENT_ABSENT {
            return Ok(PossibleBeaconContentValue::ContentAbsent);
        }

        let content_bytes = hex_decode(&s).map_err(serde::de::Error::custom)?;

        if let Ok(value) = HistoricalSummariesWithProof::from_ssz_bytes(&content_bytes) {
            return Ok(Self::ContentPresent(
                BeaconContentValue::HistoricalSummariesWithProof(value),
            ));
        }

        Err(ContentValueError::UnknownContent {
            bytes: s,
            network: "beacon".to_string(),
        })
        .map_err(serde::de::Error::custom)
    }
}

/// An error decoding a portal network content value.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum ContentValueError {
    #[error("unable to decode value SSZ bytes {input} due to {decode_error:?}")]
    DecodeSsz {
        decode_error: ssz::DecodeError,
        input: String,
    },
    #[error("could not determine content type of {bytes} from {network} network")]
    UnknownContent { bytes: String, network: String },
    /// The content value is the "0x" absent content message rather than data.
    ///
    /// This error implies that handling of the "content absent" response was skipped.
    #[error("attempted to deserialize the '0x' absent content message")]
    DeserializeAbsentContent,

    /// The content value is the "0x" absent content message rather than data.
    ///
    /// This error implies that handling of the "content absent" response was skipped.
    #[error("attempted to decode the '0x' absent content message")]
    DecodeAbsentContent,
}

impl ContentValue for HistoryContentValue {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::BlockHeaderWithProof(value) => value.as_ssz_bytes(),
            Self::BlockBody(value) => value.as_ssz_bytes(),
            Self::Receipts(value) => value.as_ssz_bytes(),
            Self::EpochAccumulator(value) => value.as_ssz_bytes(),
        }
    }

    fn decode(buf: &[u8]) -> Result<Self, ContentValueError> {
        // Catch any attempt to construct a content value from "0x" improperly.
        if buf == CONTENT_ABSENT.to_string().as_bytes() {
            return Err(ContentValueError::DecodeAbsentContent);
        }

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
        Err(ContentValueError::UnknownContent {
            bytes: hex_encode(buf),
            network: "history".to_string(),
        })
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
        let content_bytes = hex_decode(&s).map_err(serde::de::Error::custom)?;

        if let Ok(value) = HeaderWithProof::from_ssz_bytes(&content_bytes) {
            return Ok(Self::BlockHeaderWithProof(value));
        }

        if let Ok(value) = BlockBody::from_ssz_bytes(&content_bytes) {
            return Ok(Self::BlockBody(value));
        }

        // all "0x" values will return as empty receipts here
        if let Ok(value) = Receipts::from_ssz_bytes(&content_bytes) {
            return Ok(Self::Receipts(value));
        }

        if let Ok(value) = EpochAccumulator::from_ssz_bytes(&content_bytes) {
            return Ok(Self::EpochAccumulator(value));
        }

        Err(ContentValueError::UnknownContent {
            bytes: s,
            network: "history".to_string(),
        })
        .map_err(serde::de::Error::custom)
    }
}

/// A content value for the beacon network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BeaconContentValue {
    HistoricalSummariesWithProof(HistoricalSummariesWithProof),
}

impl ContentValue for BeaconContentValue {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::HistoricalSummariesWithProof(value) => value.as_ssz_bytes(),
        }
    }

    fn decode(buf: &[u8]) -> Result<Self, ContentValueError> {
        if let Ok(value) = HistoricalSummariesWithProof::from_ssz_bytes(buf) {
            return Ok(Self::HistoricalSummariesWithProof(value));
        }
        Err(ContentValueError::UnknownContent {
            bytes: hex_encode(buf),
            network: "beacon".to_string(),
        })
    }
}

impl Serialize for BeaconContentValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::HistoricalSummariesWithProof(value) => {
                serializer.serialize_str(&hex_encode(value.as_ssz_bytes()))
            }
        }
    }
}

impl<'de> Deserialize<'de> for BeaconContentValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let content_bytes = hex_decode(&s).map_err(serde::de::Error::custom)?;

        if let Ok(value) = HistoricalSummariesWithProof::from_ssz_bytes(&content_bytes) {
            return Ok(Self::HistoricalSummariesWithProof(value));
        }

        Err(ContentValueError::UnknownContent {
            bytes: s,
            network: "beacon".to_string(),
        })
        .map_err(serde::de::Error::custom)
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

    #[test]
    fn content_value_deserialization_failure_displays_debuggable_data() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let item_result = HistoryContentValue::decode(&data);
        let error = item_result.unwrap_err();
        // Test the error Debug representation
        assert_eq!(
            error,
            ContentValueError::UnknownContent {
                bytes: "0x010203040506070809".to_string(),
                network: "history".to_string()
            }
        );
        // Test the error Display representation.
        assert_eq!(
            error.to_string(),
            "could not determine content type of 0x010203040506070809 from history network"
        );
    }

    #[test]
    fn content_value_absent_raises_error_on_deserialization() {
        let data = CONTENT_ABSENT.to_string();
        let item_result = HistoryContentValue::decode(data.as_bytes());
        let error = item_result.unwrap_err();
        // Test the error Debug representation
        assert_eq!(error, ContentValueError::DecodeAbsentContent);
        // Test the error Display representation.
        assert_eq!(
            error.to_string(),
            "attempted to decode the '0x' absent content message"
        );
    }

    // TODO: add test vectors for beacon content value
}
