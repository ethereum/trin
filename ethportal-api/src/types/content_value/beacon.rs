use crate::types::consensus::fork::{ForkDigest, ForkName};
use crate::types::consensus::header_proof::HistoricalSummariesWithProof;
use crate::types::consensus::light_client::bootstrap::{
    LightClientBootstrapBellatrix, LightClientBootstrapCapella,
};
use crate::types::consensus::light_client::optimistic_update::{
    LightClientOptimisticUpdate, LightClientOptimisticUpdateBellatrix,
    LightClientOptimisticUpdateCapella,
};
use crate::types::consensus::light_client::update::{
    LightClientUpdate, LightClientUpdateBellatrix, LightClientUpdateCapella,
};
use crate::types::constants::CONTENT_ABSENT;
use crate::types::content_value::ContentValue;
use crate::utils::bytes::{hex_decode, hex_encode};
use crate::ContentValueError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::{Decode, DecodeError, Encode};
use ssz_types::typenum::U128;
use ssz_types::VariableList;

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

/// A wrapper type including a `ForkName` and `LightClientUpdate`
#[derive(Clone, Debug, PartialEq)]
pub struct ForkVersionedLightClientUpdate {
    pub fork_name: ForkName,
    pub light_client_update: LightClientUpdate,
}

impl ForkVersionedLightClientUpdate {
    pub fn encode(&self) -> Vec<u8> {
        let fork_digest = self.fork_name.as_fork_digest();

        let mut data = fork_digest.to_vec();
        data.extend(self.light_client_update.as_ssz_bytes());
        data
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let fork_digest = ForkDigest::try_from(&bytes[0..4]).map_err(|err| {
            DecodeError::BytesInvalid(format!("Unable to decode fork digest: {err:?}"))
        })?;
        let fork_name = ForkName::try_from(fork_digest).map_err(|_| {
            DecodeError::BytesInvalid(format!("Unable to decode fork name: {fork_digest:?}"))
        })?;

        let light_client_update = match fork_name {
            ForkName::Bellatrix => LightClientUpdate::Bellatrix(
                LightClientUpdateBellatrix::from_ssz_bytes(&bytes[4..])?,
            ),
            ForkName::Capella => {
                LightClientUpdate::Capella(LightClientUpdateCapella::from_ssz_bytes(&bytes[4..])?)
            }
        };

        Ok(Self {
            fork_name,
            light_client_update,
        })
    }
}

impl Decode for ForkVersionedLightClientUpdate {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::decode(bytes)
    }
}

impl Encode for ForkVersionedLightClientUpdate {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.encode());
    }

    fn ssz_bytes_len(&self) -> usize {
        self.encode().len()
    }
}

impl Serialize for ForkVersionedLightClientUpdate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let fork_digest = self.fork_name.as_fork_digest();

        let mut data = fork_digest.to_vec();
        data.extend(self.light_client_update.as_ssz_bytes());
        serializer.serialize_str(&hex_encode(data))
    }
}

/// A wrapper type including a `ForkName` and `LightClientOptimisticUpdate`
#[derive(Clone, Debug, PartialEq)]
pub struct ForkVersionedLightClientOptimisticUpdate {
    pub fork_name: ForkName,
    pub content: LightClientOptimisticUpdate,
}

impl ForkVersionedLightClientOptimisticUpdate {
    fn encode(&self) -> Vec<u8> {
        let fork_digest = self.fork_name.as_fork_digest();

        let mut data = fork_digest.to_vec();
        data.extend(self.content.as_ssz_bytes());
        data
    }

    fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let fork_digest = ForkDigest::try_from(&buf[0..4]).map_err(|err| {
            DecodeError::BytesInvalid(format!("Unable to decode fork digest: {err:?}"))
        })?;

        let fork_name = ForkName::try_from(fork_digest).map_err(|_| {
            DecodeError::BytesInvalid(format!("Unable to decode fork name: {fork_digest:?}"))
        })?;

        let content = match fork_name {
            ForkName::Bellatrix => LightClientOptimisticUpdate::Bellatrix(
                LightClientOptimisticUpdateBellatrix::from_ssz_bytes(&buf[4..])?,
            ),
            ForkName::Capella => LightClientOptimisticUpdate::Capella(
                LightClientOptimisticUpdateCapella::from_ssz_bytes(&buf[4..])?,
            ),
        };

        Ok(Self { fork_name, content })
    }
}

impl Decode for ForkVersionedLightClientOptimisticUpdate {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::decode(bytes).map_err(|err| DecodeError::BytesInvalid(format!("{err:?}")))
    }
}

impl Encode for ForkVersionedLightClientOptimisticUpdate {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.encode());
    }

    fn ssz_bytes_len(&self) -> usize {
        self.encode().len()
    }
}

/// Maximum number of `LightClientUpdate` instances in a single request is 128;
/// Defined in https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/p2p-interface.md#configuration
#[derive(Clone, Debug, PartialEq)]
pub struct LightClientUpdatesByRange(VariableList<ForkVersionedLightClientUpdate, U128>);

impl Encode for LightClientUpdatesByRange {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0.as_ssz_bytes());
    }

    fn ssz_bytes_len(&self) -> usize {
        self.0
            .iter()
            .map(|update| update.encode().len())
            .sum::<usize>()
    }
}

impl Decode for LightClientUpdatesByRange {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let updates = VariableList::<ForkVersionedLightClientUpdate, U128>::from_ssz_bytes(bytes)?;
        Ok(Self(updates))
    }
}

/// A content value for the beacon network.
#[derive(Clone, Debug, PartialEq)]
pub enum BeaconContentValue {
    HistoricalSummariesWithProof(HistoricalSummariesWithProof),
    LightClientBootstrapBellatrix(LightClientBootstrapBellatrix),
    LightClientBootstrapCapella(LightClientBootstrapCapella),
    LightClientUpdatesByRange(LightClientUpdatesByRange),
    LightClientOptimisticUpdate(ForkVersionedLightClientOptimisticUpdate),
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
            Self::LightClientUpdatesByRange(value) => value.as_ssz_bytes(),
            Self::LightClientOptimisticUpdate(value) => value.as_ssz_bytes(),
        }
    }

    fn decode(buf: &[u8]) -> Result<Self, ContentValueError> {
        if let Ok(value) = HistoricalSummariesWithProof::from_ssz_bytes(buf) {
            return Ok(Self::HistoricalSummariesWithProof(value));
        }

        if let Ok(value) = LightClientUpdatesByRange::from_ssz_bytes(buf) {
            return Ok(Self::LightClientUpdatesByRange(value));
        }

        if let Ok(value) = ForkVersionedLightClientOptimisticUpdate::from_ssz_bytes(buf) {
            return Ok(Self::LightClientOptimisticUpdate(value));
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
            Self::LightClientUpdatesByRange(value) => {
                serializer.serialize_str(&hex_encode(value.as_ssz_bytes()))
            }
            Self::LightClientOptimisticUpdate(value) => {
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

        if let Ok(value) = LightClientUpdatesByRange::from_ssz_bytes(&content_bytes) {
            return Ok(Self::LightClientUpdatesByRange(value));
        }

        if let Ok(value) = ForkVersionedLightClientOptimisticUpdate::from_ssz_bytes(&content_bytes)
        {
            return Ok(Self::LightClientOptimisticUpdate(value));
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

    #[test]
    fn light_client_updates_by_range_encode_decode() {
        let file = fs::read_to_string(
            "../test_assets/portalnet/content/beacon/light_client_updates_by_range.json",
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
                BeaconContentValue::LightClientUpdatesByRange(ref value) => {
                    assert_eq!(
                        slot_num,
                        value.0[0]
                            .light_client_update
                            .attested_header_capella()
                            .unwrap()
                            .beacon
                            .slot
                    );
                    assert_eq!(value.0.len(), 4)
                }
                _ => panic!("Invalid beacon content type!"),
            }

            assert_eq!(content_encoded, beacon_content.encode())
        }
    }

    #[test]
    fn light_client_optimistic_update_encode_decode() {
        let file = fs::read_to_string(
            "../test_assets/portalnet/content/beacon/light_client_optimistic_update.json",
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
                BeaconContentValue::LightClientOptimisticUpdate(ref value) => {
                    assert_eq!(
                        slot_num,
                        value.content.attested_header_capella().unwrap().beacon.slot
                    );
                }
                _ => panic!("Invalid beacon content type!"),
            }

            assert_eq!(content_encoded, beacon_content.encode())
        }
    }
}
