use crate::types::consensus::fork::{ForkDigest, ForkName};
use crate::types::consensus::header_proof::HistoricalSummariesWithProof;
use crate::types::consensus::light_client::bootstrap::{
    LightClientBootstrap, LightClientBootstrapBellatrix, LightClientBootstrapCapella,
};
use crate::types::consensus::light_client::finality_update::{
    LightClientFinalityUpdate, LightClientFinalityUpdateBellatrix, LightClientFinalityUpdateCapella,
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
use std::ops::Deref;

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

        if let Ok(value) = ForkVersionedLightClientBootstrap::from_ssz_bytes(&content_bytes) {
            return Ok(Self::ContentPresent(
                BeaconContentValue::LightClientBootstrap(value),
            ));
        }

        if let Ok(value) = LightClientUpdatesByRange::from_ssz_bytes(&content_bytes) {
            return Ok(Self::ContentPresent(
                BeaconContentValue::LightClientUpdatesByRange(value),
            ));
        }

        if let Ok(value) = ForkVersionedLightClientOptimisticUpdate::from_ssz_bytes(&content_bytes)
        {
            return Ok(Self::ContentPresent(
                BeaconContentValue::LightClientOptimisticUpdate(value),
            ));
        }

        if let Ok(value) = ForkVersionedLightClientFinalityUpdate::from_ssz_bytes(&content_bytes) {
            return Ok(Self::ContentPresent(
                BeaconContentValue::LightClientFinalityUpdate(value),
            ));
        }

        Err(ContentValueError::UnknownContent {
            bytes: s,
            network: "beacon".to_string(),
        })
        .map_err(serde::de::Error::custom)
    }
}

/// A wrapper type including a `ForkName` and `LightClientBootstrap`
#[derive(Clone, Debug, PartialEq)]
pub struct ForkVersionedLightClientBootstrap {
    pub fork_name: ForkName,
    pub bootstrap: LightClientBootstrap,
}

impl ForkVersionedLightClientBootstrap {
    pub fn encode(&self) -> Vec<u8> {
        let fork_digest = self.fork_name.as_fork_digest();

        let mut data = fork_digest.to_vec();
        data.extend(self.bootstrap.as_ssz_bytes());
        data
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let fork_digest = ForkDigest::try_from(&bytes[0..4]).map_err(|err| {
            DecodeError::BytesInvalid(format!("Unable to decode fork digest: {err:?}"))
        })?;
        let fork_name = ForkName::try_from(fork_digest).map_err(|_| {
            DecodeError::BytesInvalid(format!("Unable to decode fork name: {fork_digest:?}"))
        })?;

        let light_client_bootstrap = match fork_name {
            ForkName::Bellatrix => LightClientBootstrap::Bellatrix(
                LightClientBootstrapBellatrix::from_ssz_bytes(&bytes[4..])?,
            ),
            ForkName::Capella => LightClientBootstrap::Capella(
                LightClientBootstrapCapella::from_ssz_bytes(&bytes[4..])?,
            ),
        };

        Ok(Self {
            fork_name,
            bootstrap: light_client_bootstrap,
        })
    }
}

impl Decode for ForkVersionedLightClientBootstrap {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::decode(bytes)
    }
}

impl Encode for ForkVersionedLightClientBootstrap {
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

/// A wrapper type including a `ForkName` and `LightClientUpdate`
#[derive(Clone, Debug, PartialEq)]
pub struct ForkVersionedLightClientUpdate {
    pub fork_name: ForkName,
    pub update: LightClientUpdate,
}

impl ForkVersionedLightClientUpdate {
    pub fn encode(&self) -> Vec<u8> {
        let fork_digest = self.fork_name.as_fork_digest();

        let mut data = fork_digest.to_vec();
        data.extend(self.update.as_ssz_bytes());
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
            update: light_client_update,
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
        data.extend(self.update.as_ssz_bytes());
        serializer.serialize_str(&hex_encode(data))
    }
}

/// Maximum number of `LightClientUpdate` instances in a single request is 128;
/// Defined in https://github.com/ethereum/consensus-specs/blob/48143056b9be031ec810912ffc3227f7443eccd9/specs/altair/light-client/p2p-interface.md#configuration
#[derive(Clone, Debug, PartialEq)]
pub struct LightClientUpdatesByRange(pub VariableList<ForkVersionedLightClientUpdate, U128>);

impl Deref for LightClientUpdatesByRange {
    type Target = VariableList<ForkVersionedLightClientUpdate, U128>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

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

/// A wrapper type including a `ForkName` and `LightClientOptimisticUpdate`
#[derive(Clone, Debug, PartialEq)]
pub struct ForkVersionedLightClientOptimisticUpdate {
    pub fork_name: ForkName,
    pub update: LightClientOptimisticUpdate,
}

impl ForkVersionedLightClientOptimisticUpdate {
    fn encode(&self) -> Vec<u8> {
        let fork_digest = self.fork_name.as_fork_digest();

        let mut data = fork_digest.to_vec();
        data.extend(self.update.as_ssz_bytes());
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

        Ok(Self {
            fork_name,
            update: content,
        })
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

/// A wrapper type including a `ForkName` and `LightClientFinalityUpdate`
#[derive(Clone, Debug, PartialEq)]
pub struct ForkVersionedLightClientFinalityUpdate {
    pub fork_name: ForkName,
    pub update: LightClientFinalityUpdate,
}

impl ForkVersionedLightClientFinalityUpdate {
    fn encode(&self) -> Vec<u8> {
        let fork_digest = self.fork_name.as_fork_digest();

        let mut data = fork_digest.to_vec();
        data.extend(self.update.as_ssz_bytes());
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
            ForkName::Bellatrix => LightClientFinalityUpdate::Bellatrix(
                LightClientFinalityUpdateBellatrix::from_ssz_bytes(&buf[4..])?,
            ),
            ForkName::Capella => LightClientFinalityUpdate::Capella(
                LightClientFinalityUpdateCapella::from_ssz_bytes(&buf[4..])?,
            ),
        };

        Ok(Self {
            fork_name,
            update: content,
        })
    }
}

impl Decode for ForkVersionedLightClientFinalityUpdate {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::decode(bytes)
    }
}

impl Encode for ForkVersionedLightClientFinalityUpdate {
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

/// A content value for the beacon network.
#[derive(Clone, Debug, PartialEq)]
pub enum BeaconContentValue {
    HistoricalSummariesWithProof(HistoricalSummariesWithProof),
    LightClientBootstrap(ForkVersionedLightClientBootstrap),
    LightClientUpdatesByRange(LightClientUpdatesByRange),
    LightClientOptimisticUpdate(ForkVersionedLightClientOptimisticUpdate),
    LightClientFinalityUpdate(ForkVersionedLightClientFinalityUpdate),
}

impl ContentValue for BeaconContentValue {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::HistoricalSummariesWithProof(value) => value.as_ssz_bytes(),
            Self::LightClientBootstrap(value) => value.as_ssz_bytes(),
            Self::LightClientUpdatesByRange(value) => value.as_ssz_bytes(),
            Self::LightClientOptimisticUpdate(value) => value.as_ssz_bytes(),
            Self::LightClientFinalityUpdate(value) => value.as_ssz_bytes(),
        }
    }

    fn decode(buf: &[u8]) -> Result<Self, ContentValueError> {
        if let Ok(value) = HistoricalSummariesWithProof::from_ssz_bytes(buf) {
            return Ok(Self::HistoricalSummariesWithProof(value));
        }
        if let Ok(value) = ForkVersionedLightClientBootstrap::from_ssz_bytes(buf) {
            return Ok(Self::LightClientBootstrap(value));
        }
        if let Ok(value) = LightClientUpdatesByRange::from_ssz_bytes(buf) {
            return Ok(Self::LightClientUpdatesByRange(value));
        }
        if let Ok(value) = ForkVersionedLightClientOptimisticUpdate::from_ssz_bytes(buf) {
            return Ok(Self::LightClientOptimisticUpdate(value));
        }
        if let Ok(value) = ForkVersionedLightClientFinalityUpdate::from_ssz_bytes(buf) {
            return Ok(Self::LightClientFinalityUpdate(value));
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
            Self::LightClientBootstrap(value) => {
                serializer.serialize_str(&hex_encode(value.as_ssz_bytes()))
            }
            Self::LightClientUpdatesByRange(value) => {
                serializer.serialize_str(&hex_encode(value.as_ssz_bytes()))
            }
            Self::LightClientOptimisticUpdate(value) => {
                serializer.serialize_str(&hex_encode(value.as_ssz_bytes()))
            }
            Self::LightClientFinalityUpdate(value) => {
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
        if let Ok(value) = ForkVersionedLightClientBootstrap::from_ssz_bytes(&content_bytes) {
            return Ok(Self::LightClientBootstrap(value));
        }
        if let Ok(value) = LightClientUpdatesByRange::from_ssz_bytes(&content_bytes) {
            return Ok(Self::LightClientUpdatesByRange(value));
        }
        if let Ok(value) = ForkVersionedLightClientOptimisticUpdate::from_ssz_bytes(&content_bytes)
        {
            return Ok(Self::LightClientOptimisticUpdate(value));
        }
        if let Ok(value) = ForkVersionedLightClientFinalityUpdate::from_ssz_bytes(&content_bytes) {
            return Ok(Self::LightClientFinalityUpdate(value));
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
    use crate::{BeaconContentValue, ContentValue, PossibleBeaconContentValue};
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
            let content_hexstr = obj.get("content_value").unwrap().as_str().unwrap();
            let content_bytes = hex_decode(content_hexstr).unwrap();
            let beacon_content = BeaconContentValue::decode(&content_bytes).unwrap();

            match beacon_content {
                BeaconContentValue::LightClientBootstrap(ref value) => {
                    assert_eq!(
                        slot_num,
                        value.bootstrap.header_capella().unwrap().beacon.slot
                    );
                }
                _ => panic!("Invalid beacon content type!"),
            }

            assert_eq!(content_bytes, beacon_content.encode());

            assert_possible_content_value_roundtrip(beacon_content);
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
            let content_hexstr = obj.get("content_value").unwrap().as_str().unwrap();
            let content_bytes = hex_decode(content_hexstr).unwrap();
            let beacon_content = BeaconContentValue::decode(&content_bytes).unwrap();

            match beacon_content {
                BeaconContentValue::LightClientUpdatesByRange(ref updates) => {
                    assert_eq!(
                        slot_num,
                        updates[0]
                            .update
                            .attested_header_capella()
                            .unwrap()
                            .beacon
                            .slot
                    );
                    assert_eq!(updates.len(), 4)
                }
                _ => panic!("Invalid beacon content type!"),
            }

            assert_eq!(content_bytes, beacon_content.encode());

            assert_possible_content_value_roundtrip(beacon_content);
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
            let content_hexstr = obj.get("content_value").unwrap().as_str().unwrap();
            let content_bytes = hex_decode(content_hexstr).unwrap();
            let beacon_content = BeaconContentValue::decode(&content_bytes).unwrap();

            match beacon_content {
                BeaconContentValue::LightClientOptimisticUpdate(ref value) => {
                    assert_eq!(
                        slot_num,
                        value.update.attested_header_capella().unwrap().beacon.slot
                    );
                }
                _ => panic!("Invalid beacon content type!"),
            }

            assert_eq!(content_bytes, beacon_content.encode());

            assert_possible_content_value_roundtrip(beacon_content);
        }
    }

    #[test]
    fn light_client_finality_update_encode_decode() {
        let file = fs::read_to_string(
            "../test_assets/portalnet/content/beacon/light_client_finality_update.json",
        )
        .unwrap();
        let json: Value = serde_json::from_str(&file).unwrap();
        let json = json.as_object().unwrap();
        for (slot_num, obj) in json {
            let slot_num: u64 = slot_num.parse().unwrap();
            let content_hexstr = obj.get("content_value").unwrap().as_str().unwrap();
            let content_bytes = hex_decode(content_hexstr).unwrap();
            let beacon_content = BeaconContentValue::decode(&content_bytes).unwrap();

            match beacon_content {
                BeaconContentValue::LightClientFinalityUpdate(ref value) => {
                    assert_eq!(
                        slot_num,
                        value.update.attested_header_capella().unwrap().beacon.slot
                    );
                }
                _ => panic!("Invalid beacon content type!"),
            }

            assert_eq!(content_bytes, beacon_content.encode());

            assert_possible_content_value_roundtrip(beacon_content);
        }
    }

    fn assert_possible_content_value_roundtrip(beacon_content: BeaconContentValue) {
        let expected_possible_content_value =
            PossibleBeaconContentValue::ContentPresent(beacon_content);
        let json_str = serde_json::to_string(&expected_possible_content_value).unwrap();
        let possible_content_value: PossibleBeaconContentValue =
            serde_json::from_str(&json_str).unwrap();

        assert_eq!(expected_possible_content_value, possible_content_value);
    }
}
