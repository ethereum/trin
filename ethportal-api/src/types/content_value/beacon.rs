use crate::types::consensus::fork::{ForkDigest, ForkName};
use crate::types::consensus::header_proof::HistoricalSummariesWithProof;
use crate::types::consensus::light_client::bootstrap::{
    LightClientBootstrapBellatrix, LightClientBootstrapCapella,
};
use crate::types::constants::CONTENT_ABSENT;
use crate::types::content_value::ContentValue;
use crate::utils::bytes::{hex_decode, hex_encode};
use crate::ContentValueError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::{Decode, Encode};

#[derive(Clone, Debug, PartialEq)]
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
#[derive(Clone, Debug, PartialEq)]
pub enum BeaconContentValue {
    HistoricalSummariesWithProof(HistoricalSummariesWithProof),
    LightClientBootstrapBellatrix(LightClientBootstrapBellatrix),
    LightClientBootstrapCapella(LightClientBootstrapCapella),
}

impl ContentValue for BeaconContentValue {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::HistoricalSummariesWithProof(value) => value.as_ssz_bytes(),
            Self::LightClientBootstrapBellatrix(value) => {
                let mut data = ForkName::Bellatrix.as_fork_digest().to_vec();
                data.extend(value.as_ssz_bytes());
                data
            }
            Self::LightClientBootstrapCapella(value) => {
                let mut data = ForkName::Capella.as_fork_digest().to_vec();
                data.extend(value.as_ssz_bytes());
                data
            }
        }
    }

    fn decode(buf: &[u8]) -> Result<Self, ContentValueError> {
        if let Ok(value) = HistoricalSummariesWithProof::from_ssz_bytes(buf) {
            return Ok(Self::HistoricalSummariesWithProof(value));
        }
        let fork_digest =
            ForkDigest::try_from(&buf[0..4]).map_err(|_| ContentValueError::UnknownForkDigest {
                bytes: hex_encode(buf),
                network: "beacon".to_string(),
            })?;

        let fork_name =
            ForkName::try_from(fork_digest).map_err(|_| ContentValueError::UnknownForkName {
                bytes: hex_encode(fork_digest),
                network: "beacon".to_string(),
            })?;

        match fork_name {
            ForkName::Bellatrix => {
                if let Ok(value) = LightClientBootstrapBellatrix::from_ssz_bytes(&buf[4..]) {
                    return Ok(Self::LightClientBootstrapBellatrix(value));
                }
            }
            ForkName::Capella => {
                if let Ok(value) = LightClientBootstrapCapella::from_ssz_bytes(&buf[4..]) {
                    return Ok(Self::LightClientBootstrapCapella(value));
                }
            }
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
            Self::LightClientBootstrapBellatrix(value) => {
                let mut data = ForkName::Bellatrix.as_fork_digest().to_vec();
                data.extend(value.as_ssz_bytes());

                serializer.serialize_str(&hex_encode(data))
            }
            Self::LightClientBootstrapCapella(value) => {
                let mut data = ForkName::Bellatrix.as_fork_digest().to_vec();
                data.extend(value.as_ssz_bytes());

                serializer.serialize_str(&hex_encode(data))
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

        let fork_digest = ForkDigest::try_from(&content_bytes[0..4])
            .map_err(|_| ContentValueError::UnknownForkDigest {
                bytes: hex_encode(&content_bytes[0..4]),
                network: "beacon".to_string(),
            })
            .map_err(serde::de::Error::custom)?;

        let fork_name = ForkName::try_from(fork_digest)
            .map_err(|_| ContentValueError::UnknownForkName {
                bytes: hex_encode(fork_digest),
                network: "beacon".to_string(),
            })
            .map_err(serde::de::Error::custom)?;

        match fork_name {
            ForkName::Bellatrix => {
                if let Ok(value) =
                    LightClientBootstrapBellatrix::from_ssz_bytes(&content_bytes[4..])
                {
                    return Ok(Self::LightClientBootstrapBellatrix(value));
                }
            }
            ForkName::Capella => {
                if let Ok(value) = LightClientBootstrapCapella::from_ssz_bytes(&content_bytes[4..])
                {
                    return Ok(Self::LightClientBootstrapCapella(value));
                }
            }
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
    use crate::utils::bytes::hex_decode;
    use crate::{BeaconContentValue, ContentValue};
    use serde_json::Value;
    use std::fs;

    #[test]
    fn light_client_bootstrap_encode_decode() {
        let file = fs::read_to_string(
            "../test_assets/portalnet/content/beacon/light_client_bootstrap.json",
        )
        .unwrap();
        let json: Value = serde_json::from_str(&file).unwrap();
        let json = json.as_object().unwrap();
        for (slot_num, obj) in json {
            let slot_num: u64 = slot_num.parse().unwrap();
            let content = obj.get("content_value").unwrap().as_str().unwrap();
            let content_encoded = hex_decode(content).unwrap();
            let beacon_content = BeaconContentValue::decode(&content_encoded).unwrap();

            match beacon_content {
                BeaconContentValue::LightClientBootstrapCapella(ref value) => {
                    assert_eq!(slot_num, value.header.beacon.slot);
                }
                _ => panic!("Invalid beacon content type!"),
            }

            assert_eq!(content_encoded, beacon_content.encode())
        }
    }
}
