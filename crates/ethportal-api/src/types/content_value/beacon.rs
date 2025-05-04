use std::ops::Deref;

use serde::{Serialize, Serializer};
use ssz::{Decode, DecodeError, Encode};
use ssz_types::{typenum::U128, VariableList};

use crate::{
    consensus::historical_summaries::{
        HistoricalSummariesWithProof, HistoricalSummariesWithProofElectra,
    },
    light_client::{
        bootstrap::{LightClientBootstrapDeneb, LightClientBootstrapElectra},
        finality_update::{LightClientFinalityUpdateDeneb, LightClientFinalityUpdateElectra},
        optimistic_update::{LightClientOptimisticUpdateDeneb, LightClientOptimisticUpdateElectra},
        update::{LightClientUpdateDeneb, LightClientUpdateElectra},
    },
    types::{
        consensus::{
            fork::{ForkDigest, ForkName},
            historical_summaries::HistoricalSummariesWithProofDeneb,
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
        network::Subnetwork,
    },
    utils::bytes::hex_encode,
    BeaconContentKey, ContentValueError, RawContentValue,
};

/// A wrapper type including a `ForkName` and `LightClientBootstrap`
#[derive(Clone, Debug, PartialEq)]
pub struct ForkVersionedLightClientBootstrap {
    pub fork_name: ForkName,
    pub bootstrap: LightClientBootstrap,
}

impl From<LightClientBootstrap> for ForkVersionedLightClientBootstrap {
    fn from(bootstrap: LightClientBootstrap) -> Self {
        let fork_name = match &bootstrap {
            LightClientBootstrap::Bellatrix(_) => ForkName::Bellatrix,
            LightClientBootstrap::Capella(_) => ForkName::Capella,
            LightClientBootstrap::Deneb(_) => ForkName::Deneb,
            LightClientBootstrap::Electra(_) => ForkName::Electra,
        };
        Self {
            fork_name,
            bootstrap,
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
            ForkName::Electra => LightClientBootstrap::Electra(
                LightClientBootstrapElectra::from_ssz_bytes(&bytes[4..])?,
            ),
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
            LightClientBootstrap::Electra(bootstrap) => bootstrap.header.beacon.slot,
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

impl From<LightClientUpdate> for ForkVersionedLightClientUpdate {
    fn from(update: LightClientUpdate) -> Self {
        let fork_name = match &update {
            LightClientUpdate::Bellatrix(_) => ForkName::Bellatrix,
            LightClientUpdate::Capella(_) => ForkName::Capella,
            LightClientUpdate::Deneb(_) => ForkName::Deneb,
            LightClientUpdate::Electra(_) => ForkName::Electra,
        };
        Self { fork_name, update }
    }
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
            ForkName::Electra => {
                LightClientUpdate::Electra(LightClientUpdateElectra::from_ssz_bytes(&bytes[4..])?)
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

impl From<LightClientOptimisticUpdate> for ForkVersionedLightClientOptimisticUpdate {
    fn from(update: LightClientOptimisticUpdate) -> Self {
        let fork_name = match &update {
            LightClientOptimisticUpdate::Bellatrix(_) => ForkName::Bellatrix,
            LightClientOptimisticUpdate::Capella(_) => ForkName::Capella,
            LightClientOptimisticUpdate::Deneb(_) => ForkName::Deneb,
            LightClientOptimisticUpdate::Electra(_) => ForkName::Electra,
        };
        Self { fork_name, update }
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
            ForkName::Electra => LightClientOptimisticUpdate::Electra(
                LightClientOptimisticUpdateElectra::from_ssz_bytes(&buf[4..])?,
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

impl From<LightClientFinalityUpdate> for ForkVersionedLightClientFinalityUpdate {
    fn from(update: LightClientFinalityUpdate) -> Self {
        let fork_name = match &update {
            LightClientFinalityUpdate::Bellatrix(_) => ForkName::Bellatrix,
            LightClientFinalityUpdate::Capella(_) => ForkName::Capella,
            LightClientFinalityUpdate::Deneb(_) => ForkName::Deneb,
            LightClientFinalityUpdate::Electra(_) => ForkName::Electra,
        };
        Self { fork_name, update }
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
            ForkName::Electra => LightClientFinalityUpdate::Electra(
                LightClientFinalityUpdateElectra::from_ssz_bytes(&buf[4..])?,
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
            LightClientFinalityUpdate::Electra(update) => update.finalized_header.beacon.slot,
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

impl From<HistoricalSummariesWithProof> for ForkVersionedHistoricalSummariesWithProof {
    fn from(historical_summaries_with_proof: HistoricalSummariesWithProof) -> Self {
        let fork_name = match &historical_summaries_with_proof {
            HistoricalSummariesWithProof::Deneb(_) => ForkName::Deneb,
            HistoricalSummariesWithProof::Electra(_) => ForkName::Electra,
        };
        Self {
            fork_name,
            historical_summaries_with_proof,
        }
    }
}

impl ForkVersionedHistoricalSummariesWithProof {
    pub fn epoch(&self) -> u64 {
        *self.historical_summaries_with_proof.epoch()
    }
}

impl Encode for ForkVersionedHistoricalSummariesWithProof {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.fork_name.as_fork_digest().ssz_append(buf);
        self.historical_summaries_with_proof.ssz_append(buf);
    }

    fn ssz_fixed_len() -> usize {
        ssz::BYTES_PER_LENGTH_OFFSET
    }

    fn ssz_bytes_len(&self) -> usize {
        self.fork_name.as_fork_digest().ssz_bytes_len()
            + self.historical_summaries_with_proof.ssz_bytes_len()
    }
}

impl Decode for ForkVersionedHistoricalSummariesWithProof {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_fixed_len() -> usize {
        ssz::BYTES_PER_LENGTH_OFFSET
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let fork_digest_len = <ForkDigest as Decode>::ssz_fixed_len();
        let Some((fork_digest_bytes, historical_summaries_with_proof_bytes)) =
            bytes.split_at_checked(fork_digest_len)
        else {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: fork_digest_len,
            });
        };

        let fork_digest = ForkDigest::from_ssz_bytes(fork_digest_bytes)?;
        let fork_name = match ForkName::try_from(fork_digest) {
            Ok(fork_name) => fork_name,
            Err(err) => return Err(DecodeError::BytesInvalid(err.to_string())),
        };

        let historical_summaries_with_proof = match fork_name {
            ForkName::Bellatrix | ForkName::Capella => {
                return Err(DecodeError::BytesInvalid(format!(
                    "HistoricalSummariesWithProof not supported for fork digest: {fork_digest:?}"
                )))
            }
            ForkName::Deneb => HistoricalSummariesWithProof::Deneb(
                HistoricalSummariesWithProofDeneb::from_ssz_bytes(
                    historical_summaries_with_proof_bytes,
                )?,
            ),
            ForkName::Electra => HistoricalSummariesWithProof::Electra(
                HistoricalSummariesWithProofElectra::from_ssz_bytes(
                    historical_summaries_with_proof_bytes,
                )?,
            ),
        };
        Ok(Self {
            fork_name,
            historical_summaries_with_proof,
        })
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
    type TContentKey = BeaconContentKey;

    fn encode(&self) -> RawContentValue {
        match self {
            Self::HistoricalSummariesWithProof(value) => value.as_ssz_bytes().into(),
            Self::LightClientBootstrap(value) => value.as_ssz_bytes().into(),
            Self::LightClientUpdatesByRange(value) => value.as_ssz_bytes().into(),
            Self::LightClientOptimisticUpdate(value) => value.as_ssz_bytes().into(),
            Self::LightClientFinalityUpdate(value) => value.as_ssz_bytes().into(),
        }
    }

    fn decode(key: &Self::TContentKey, buf: &[u8]) -> Result<Self, ContentValueError> {
        match key {
            BeaconContentKey::LightClientBootstrap(_) => {
                if let Ok(value) = ForkVersionedLightClientBootstrap::from_ssz_bytes(buf) {
                    return Ok(Self::LightClientBootstrap(value));
                }
            }
            BeaconContentKey::LightClientUpdatesByRange(_) => {
                if let Ok(value) = LightClientUpdatesByRange::from_ssz_bytes(buf) {
                    return Ok(Self::LightClientUpdatesByRange(value));
                }
            }
            BeaconContentKey::LightClientFinalityUpdate(_) => {
                if let Ok(value) = ForkVersionedLightClientFinalityUpdate::from_ssz_bytes(buf) {
                    return Ok(Self::LightClientFinalityUpdate(value));
                }
            }
            BeaconContentKey::LightClientOptimisticUpdate(_) => {
                if let Ok(value) = ForkVersionedLightClientOptimisticUpdate::from_ssz_bytes(buf) {
                    return Ok(Self::LightClientOptimisticUpdate(value));
                }
            }
            BeaconContentKey::HistoricalSummariesWithProof(_) => {
                if let Ok(value) = ForkVersionedHistoricalSummariesWithProof::from_ssz_bytes(buf) {
                    return Ok(Self::HistoricalSummariesWithProof(value));
                }
            }
        }
        Err(ContentValueError::UnknownContent {
            bytes: hex_encode(buf),
            subnetwork: Subnetwork::Beacon,
        })
    }
}

#[cfg(test)]
mod test {
    use serde::Deserialize;

    use super::*;
    use crate::test_utils::{read_yaml_portal_spec_tests_file, types::ContentItem};

    #[rstest::rstest]
    #[case("capella", 6718368)]
    #[case("deneb", 10248000)]
    fn light_client_bootstrap_encode_decode(#[case] fork_name: &str, #[case] expected_slot: u64) {
        let test_data: ContentItem<BeaconContentKey> = read_yaml_portal_spec_tests_file(format!(
            "tests/mainnet/beacon_chain/light_client/{fork_name}/bootstrap.yaml",
        ))
        .unwrap();
        let content_value: BeaconContentValue = test_data.content_value().unwrap();

        assert_str_roundtrip(test_data.content_key, content_value.clone());

        match content_value {
            BeaconContentValue::LightClientBootstrap(value) => {
                assert_eq!(expected_slot, value.get_slot());
            }
            _ => panic!("Invalid beacon content type!"),
        }
    }

    #[rstest::rstest]
    #[case("capella", 6684738)]
    #[case("deneb", 10240088)]
    fn light_client_updates_by_range_encode_decode(
        #[case] fork_name: &str,
        #[case] expected_slot: u64,
    ) {
        let test_data: ContentItem<BeaconContentKey> = read_yaml_portal_spec_tests_file(format!(
            "tests/mainnet/beacon_chain/light_client/{fork_name}/updates.yaml",
        ))
        .unwrap();
        let content_value: BeaconContentValue = test_data.content_value().unwrap();

        assert_str_roundtrip(test_data.content_key, content_value.clone());

        let update = match content_value {
            BeaconContentValue::LightClientUpdatesByRange(value) => value[0].update.clone(),
            _ => panic!("Invalid beacon content type!"),
        };
        let actual_slot = match fork_name {
            "capella" => update.attested_header_capella().unwrap().beacon.slot,
            "deneb" => update.attested_header_deneb().unwrap().beacon.slot,
            _ => panic!("Invalid fork name!"),
        };
        assert_eq!(actual_slot, expected_slot);
    }

    #[rstest::rstest]
    #[case("capella", 6718463)]
    #[case("deneb", 10248457)]
    fn light_client_optimistic_update_encode_decode(
        #[case] fork_name: &str,
        #[case] expected_slot: u64,
    ) {
        let test_data: ContentItem<BeaconContentKey> = read_yaml_portal_spec_tests_file(format!(
            "tests/mainnet/beacon_chain/light_client/{fork_name}/optimistic_update.yaml",
        ))
        .unwrap();
        let content_value: BeaconContentValue = test_data.content_value().unwrap();

        assert_str_roundtrip(test_data.content_key, content_value.clone());

        let update = match content_value {
            BeaconContentValue::LightClientOptimisticUpdate(value) => value.update,
            _ => panic!("Invalid beacon content type!"),
        };
        let actual_slot = match fork_name {
            "capella" => update.attested_header_capella().unwrap().beacon.slot,
            "deneb" => update.attested_header_deneb().unwrap().beacon.slot,
            _ => panic!("Invalid fork name!"),
        };
        assert_eq!(actual_slot, expected_slot);
    }

    #[rstest::rstest]
    #[case("capella", 6718463)]
    #[case("deneb", 10248453)]
    fn light_client_finality_update_encode_decode(
        #[case] fork_name: &str,
        #[case] expected_slot: u64,
    ) {
        let test_data: ContentItem<BeaconContentKey> = read_yaml_portal_spec_tests_file(format!(
            "tests/mainnet/beacon_chain/light_client/{fork_name}/finality_update.yaml",
        ))
        .unwrap();
        let content_value: BeaconContentValue = test_data.content_value().unwrap();

        assert_str_roundtrip(test_data.content_key, content_value.clone());

        let update = match content_value {
            BeaconContentValue::LightClientFinalityUpdate(value) => value.update,
            _ => panic!("Invalid beacon content type!"),
        };
        let actual_slot = match fork_name {
            "capella" => update.attested_header_capella().unwrap().beacon.slot,
            "deneb" => update.attested_header_deneb().unwrap().beacon.slot,
            _ => panic!("Invalid fork name!"),
        };
        assert_eq!(actual_slot, expected_slot);
    }

    #[test]
    fn deneb_historical_summaries_with_proof_encode_decode() {
        let value: serde_yaml::Value = read_yaml_portal_spec_tests_file(
            "tests/mainnet/beacon_chain/historical_summaries_with_proof/deneb/historical_summaries_with_proof.yaml",
        ).unwrap();
        let content_key = BeaconContentKey::deserialize(&value["content_key"]).unwrap();
        let content_bytes = RawContentValue::deserialize(&value["content_value"]).unwrap();
        let beacon_content = BeaconContentValue::decode(&content_key, &content_bytes).unwrap();
        let expected_epoch = <u64>::deserialize(&value["epoch"]).unwrap();

        match &beacon_content {
            BeaconContentValue::HistoricalSummariesWithProof(content) => {
                assert_eq!(ForkName::Deneb, content.fork_name);

                let Ok(historical_summaries_with_proof) =
                    content.historical_summaries_with_proof.as_deneb()
                else {
                    panic!("Expected Deneb historical summaries, actual: {content:?}");
                };
                assert_eq!(expected_epoch, historical_summaries_with_proof.epoch);
            }
            _ => panic!("Invalid beacon content type!"),
        }

        assert_eq!(content_bytes, beacon_content.encode());

        assert_str_roundtrip(content_key, beacon_content);
    }

    fn assert_str_roundtrip(content_key: BeaconContentKey, content_value: BeaconContentValue) {
        let hex_str = content_value.to_hex();
        assert_eq!(
            BeaconContentValue::from_hex(&content_key, &hex_str).unwrap(),
            content_value,
            "to_hex() + from_hex() doesn't match: {hex_str}"
        );
    }
}
