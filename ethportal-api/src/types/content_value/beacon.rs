use crate::types::consensus::header_proof::HistoricalSummariesWithProof;
use crate::types::constants::CONTENT_ABSENT;
use crate::types::content_value::ContentValue;
use crate::utils::bytes::{hex_decode, hex_encode};
use crate::ContentValueError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::{Decode, Encode};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PossibleBeaconContentValue {
    ContentPresent(BeaconContentValue),
    ContentAbsent,
}

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
    // TODO: add test vectors for beacon content value
}
