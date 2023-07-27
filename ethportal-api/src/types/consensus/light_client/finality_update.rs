use crate::types::consensus::body::SyncAggregate;
use crate::types::consensus::fork::ForkName;
use crate::types::consensus::light_client::header::{
    LightClientHeaderBellatrix, LightClientHeaderCapella,
};
use crate::types::consensus::light_client::update::FinalizedRootProofLen;
use ethereum_types::H256;
use serde::{Deserialize, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::FixedVector;
use superstruct::superstruct;

/// A LightClientFinalityUpdate is the update that
/// signal a new finalized beacon block header for the light client sync protocol.
#[superstruct(
    variants(Bellatrix, Capella),
    variant_attributes(
        derive(Debug, Clone, Serialize, Deserialize, Encode, Decode,),
        serde(deny_unknown_fields),
    )
)]
#[derive(Debug, Clone, Serialize, Deserialize, Encode)]
#[ssz(enum_behaviour = "transparent")]
pub struct LightClientFinalityUpdate {
    /// The last `LightClientHeader` from the last attested block by the sync committee.
    #[superstruct(only(Bellatrix), partial_getter(rename = "attested_header_bellatrix"))]
    pub attested_header: LightClientHeaderBellatrix,
    #[superstruct(only(Capella), partial_getter(rename = "attested_header_capella"))]
    pub attested_header: LightClientHeaderCapella,
    /// The last `LightClientHeader` from the last attested finalized block (end of epoch).
    #[superstruct(only(Bellatrix), partial_getter(rename = "finalized_header_bellatrix"))]
    pub finalized_header: LightClientHeaderBellatrix,
    #[superstruct(only(Capella), partial_getter(rename = "finalized_header_capella"))]
    pub finalized_header: LightClientHeaderCapella,
    /// Merkle proof attesting finalized header.
    pub finality_branch: FixedVector<H256, FinalizedRootProofLen>,
    /// current sync aggregate
    pub sync_aggregate: SyncAggregate,
    /// Slot of the sync aggregated signature
    pub signature_slot: u64,
}

impl LightClientFinalityUpdate {
    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Bellatrix => {
                LightClientFinalityUpdateBellatrix::from_ssz_bytes(bytes).map(Self::Bellatrix)
            }
            ForkName::Capella => {
                LightClientFinalityUpdateCapella::from_ssz_bytes(bytes).map(Self::Capella)
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use ::ssz::Encode;
    use rstest::rstest;
    use serde_json::Value;

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    #[case("case_2")]
    #[case("case_3")]
    #[case("case_4")]
    fn serde_light_client_finality_update_bellatrix(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/bellatrix/LightClientFinalityUpdate/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: LightClientFinalityUpdateBellatrix =
            serde_json::from_value(value.clone()).unwrap();
        let serialized = serde_json::to_value(content).unwrap();
        assert_eq!(serialized, value);
    }

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    #[case("case_2")]
    #[case("case_3")]
    #[case("case_4")]
    fn ssz_light_client_finality_update_bellatrix(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/bellatrix/LightClientFinalityUpdate/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: LightClientFinalityUpdateBellatrix = serde_json::from_value(value).unwrap();

        let compressed = std::fs::read(format!(
            "../test_assets/beacon/bellatrix/LightClientFinalityUpdate/ssz_random/{case}/serialized.ssz_snappy"
        ))
            .expect("cannot find test asset");
        let mut decoder = snap::raw::Decoder::new();
        let expected = decoder.decompress_vec(&compressed).unwrap();
        LightClientFinalityUpdate::from_ssz_bytes(&expected, ForkName::Bellatrix).unwrap();
        assert_eq!(content.as_ssz_bytes(), expected);
    }

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    #[case("case_2")]
    #[case("case_3")]
    #[case("case_4")]
    fn serde_light_client_finality_update_capella(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/capella/LightClientFinalityUpdate/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: LightClientFinalityUpdateCapella =
            serde_json::from_value(value.clone()).unwrap();
        let serialized = serde_json::to_value(content).unwrap();
        assert_eq!(serialized, value);
    }

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    #[case("case_2")]
    #[case("case_3")]
    #[case("case_4")]
    fn ssz_light_client_finality_update_capella(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/capella/LightClientFinalityUpdate/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: LightClientFinalityUpdateCapella = serde_json::from_value(value).unwrap();

        let compressed = std::fs::read(format!(
            "../test_assets/beacon/capella/LightClientFinalityUpdate/ssz_random/{case}/serialized.ssz_snappy"
        ))
            .expect("cannot find test asset");
        let mut decoder = snap::raw::Decoder::new();
        let expected = decoder.decompress_vec(&compressed).unwrap();
        LightClientFinalityUpdate::from_ssz_bytes(&expected, ForkName::Capella).unwrap();
        assert_eq!(content.as_ssz_bytes(), expected);
    }
}
