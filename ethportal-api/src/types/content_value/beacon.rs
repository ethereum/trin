use crate::{
    light_client::{
        bootstrap::LightClientBootstrapDeneb, finality_update::LightClientFinalityUpdateDeneb,
        optimistic_update::LightClientOptimisticUpdateDeneb, update::LightClientUpdateDeneb,
    },
    types::{
        consensus::{
            fork::{ForkDigest, ForkName},
            historical_summaries::HistoricalSummariesWithProof,
            light_client::{
                bootstrap::{
                    LightClientBootstrap, LightClientBootstrapBellatrix,
                    LightClientBootstrapCapella,
                },
                finality_update::{
                    LightClientFinalityUpdate, LightClientFinalityUpdateBellatrix,
                    LightClientFinalityUpdateCapella,
                },
                optimistic_update::{
                    LightClientOptimisticUpdate, LightClientOptimisticUpdateBellatrix,
                    LightClientOptimisticUpdateCapella,
                },
                update::{LightClientUpdate, LightClientUpdateBellatrix, LightClientUpdateCapella},
            },
        },
        content_value::ContentValue,
    },
    utils::bytes::hex_encode,
    ContentValueError,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::{Decode, DecodeError, Encode};
use ssz_types::{typenum::U128, VariableList};
use std::ops::Deref;

/// A wrapper type including a `ForkName` and `LightClientBootstrap`
#[derive(Clone, Debug, PartialEq)]
pub struct ForkVersionedLightClientBootstrap {
    pub fork_name: ForkName,
    pub bootstrap: LightClientBootstrap,
}

impl From<LightClientBootstrapCapella> for ForkVersionedLightClientBootstrap {
    fn from(bootstrap: LightClientBootstrapCapella) -> Self {
        Self {
            fork_name: ForkName::Capella,
            bootstrap: LightClientBootstrap::Capella(bootstrap),
        }
    }
}

impl From<LightClientBootstrapDeneb> for ForkVersionedLightClientBootstrap {
    fn from(bootstrap: LightClientBootstrapDeneb) -> Self {
        Self {
            fork_name: ForkName::Deneb,
            bootstrap: LightClientBootstrap::Deneb(bootstrap),
        }
    }
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
            ForkName::Deneb => {
                LightClientBootstrap::Deneb(LightClientBootstrapDeneb::from_ssz_bytes(&bytes[4..])?)
            }
        };

        Ok(Self {
            fork_name,
            bootstrap: light_client_bootstrap,
        })
    }

    /// Get the slot of the `LightClientBootstrap`
    pub fn get_slot(&self) -> u64 {
        match &self.bootstrap {
            LightClientBootstrap::Bellatrix(bootstrap) => bootstrap.header.beacon.slot,
            LightClientBootstrap::Capella(bootstrap) => bootstrap.header.beacon.slot,
            LightClientBootstrap::Deneb(bootstrap) => bootstrap.header.beacon.slot,
        }
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
            ForkName::Deneb => {
                LightClientUpdate::Deneb(LightClientUpdateDeneb::from_ssz_bytes(&bytes[4..])?)
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

impl From<LightClientOptimisticUpdateCapella> for ForkVersionedLightClientOptimisticUpdate {
    fn from(update: LightClientOptimisticUpdateCapella) -> Self {
        Self {
            fork_name: ForkName::Capella,
            update: LightClientOptimisticUpdate::Capella(update),
        }
    }
}

impl From<LightClientOptimisticUpdateDeneb> for ForkVersionedLightClientOptimisticUpdate {
    fn from(update: LightClientOptimisticUpdateDeneb) -> Self {
        Self {
            fork_name: ForkName::Deneb,
            update: LightClientOptimisticUpdate::Deneb(update),
        }
    }
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
            ForkName::Deneb => LightClientOptimisticUpdate::Deneb(
                LightClientOptimisticUpdateDeneb::from_ssz_bytes(&buf[4..])?,
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

impl From<LightClientFinalityUpdateCapella> for ForkVersionedLightClientFinalityUpdate {
    fn from(update: LightClientFinalityUpdateCapella) -> Self {
        Self {
            fork_name: ForkName::Capella,
            update: LightClientFinalityUpdate::Capella(update),
        }
    }
}
impl From<LightClientFinalityUpdateDeneb> for ForkVersionedLightClientFinalityUpdate {
    fn from(update: LightClientFinalityUpdateDeneb) -> Self {
        Self {
            fork_name: ForkName::Deneb,
            update: LightClientFinalityUpdate::Deneb(update),
        }
    }
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
            ForkName::Deneb => LightClientFinalityUpdate::Deneb(
                LightClientFinalityUpdateDeneb::from_ssz_bytes(&buf[4..])?,
            ),
        };

        Ok(Self {
            fork_name,
            update: content,
        })
    }

    /// Get the finalized slot of the `LightClientFinalityUpdate`
    pub fn get_finalized_slot(&self) -> u64 {
        match &self.update {
            LightClientFinalityUpdate::Bellatrix(update) => update.finalized_header.beacon.slot,
            LightClientFinalityUpdate::Capella(update) => update.finalized_header.beacon.slot,
            LightClientFinalityUpdate::Deneb(update) => update.finalized_header.beacon.slot,
        }
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

/// A wrapper type including a `ForkName` and `HistoricalSummariesWithProof`
#[derive(Clone, Debug, PartialEq)]
pub struct ForkVersionedHistoricalSummariesWithProof {
    pub fork_name: ForkName,
    pub historical_summaries_with_proof: HistoricalSummariesWithProof,
}

impl ForkVersionedHistoricalSummariesWithProof {
    pub fn encode(&self) -> Vec<u8> {
        let fork_digest = self.fork_name.as_fork_digest();

        let mut data = fork_digest.to_vec();
        data.extend(self.historical_summaries_with_proof.as_ssz_bytes());
        data
    }

    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let fork_digest = ForkDigest::try_from(&buf[0..4]).map_err(|err| {
            DecodeError::BytesInvalid(format!("Unable to decode fork digest: {err:?}"))
        })?;
        let fork_name = ForkName::try_from(fork_digest).map_err(|_| {
            DecodeError::BytesInvalid(format!("Unable to decode fork name: {fork_digest:?}"))
        })?;
        let summaries_with_proof = HistoricalSummariesWithProof::from_ssz_bytes(&buf[4..])?;

        Ok(Self {
            fork_name,
            historical_summaries_with_proof: summaries_with_proof,
        })
    }
}

impl Decode for ForkVersionedHistoricalSummariesWithProof {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::decode(bytes)
    }
}

impl Encode for ForkVersionedHistoricalSummariesWithProof {
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
#[allow(clippy::large_enum_variant)]
pub enum BeaconContentValue {
    HistoricalSummariesWithProof(ForkVersionedHistoricalSummariesWithProof),
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
        if let Ok(value) = ForkVersionedHistoricalSummariesWithProof::from_ssz_bytes(buf) {
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
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for BeaconContentValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        consensus::fork::ForkName, utils::bytes::hex_decode, BeaconContentValue, ContentValue,
    };
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

    #[test]
    fn historical_summaries_with_proof_encode_decode() {
        let file = fs::read_to_string("./../portal-spec-tests/tests/mainnet/beacon_chain/historical_summaries_with_proof/deneb/historical_summaries_with_proof.yaml").unwrap();
        let value: serde_yaml::Value = serde_yaml::from_str(&file).unwrap();
        let content_value = value.get("content_value").unwrap().as_str().unwrap();
        let historical_summaries_with_proof_bytes = hex_decode(content_value).unwrap();
        let historical_summaries_with_proof =
            BeaconContentValue::decode(&historical_summaries_with_proof_bytes).unwrap();
        let expected_epoch = value.get("epoch").unwrap().as_u64().unwrap();

        match historical_summaries_with_proof {
            BeaconContentValue::HistoricalSummariesWithProof(ref content) => {
                assert_eq!(
                    expected_epoch,
                    content.historical_summaries_with_proof.epoch
                );
                assert_eq!(ForkName::Deneb, content.fork_name);
            }
            _ => panic!("Invalid beacon content type!"),
        }

        assert_eq!(
            historical_summaries_with_proof_bytes,
            historical_summaries_with_proof.encode()
        );
    }

    fn assert_possible_content_value_roundtrip(beacon_content: BeaconContentValue) {
        let json_str = serde_json::to_string(&beacon_content).unwrap();
        let possible_content_value: BeaconContentValue = serde_json::from_str(&json_str).unwrap();

        assert_eq!(beacon_content, possible_content_value);
    }
}
