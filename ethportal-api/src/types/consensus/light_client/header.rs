use crate::types::consensus::execution_payload::ExecutionPayloadHeaderCapella;
use crate::types::consensus::fork::ForkName;
use crate::types::consensus::header::BeaconBlockHeader;
use ethereum_types::H256;
use serde::{Deserialize, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::typenum::U4;
use ssz_types::FixedVector;
use superstruct::superstruct;

pub type ExecutionBranchLen = U4;

#[superstruct(
    variants(Bellatrix, Capella),
    variant_attributes(
        derive(Debug, Clone, Serialize, PartialEq, Deserialize, Encode, Decode,),
        serde(deny_unknown_fields),
    )
)]
#[derive(Debug, Clone, Serialize, Deserialize, Encode)]
#[ssz(enum_behaviour = "transparent")]
pub struct LightClientHeader {
    pub beacon: BeaconBlockHeader,
    #[superstruct(only(Capella))]
    pub execution: ExecutionPayloadHeaderCapella,
    #[superstruct(only(Capella))]
    pub execution_branch: FixedVector<H256, ExecutionBranchLen>,
}

impl LightClientHeader {
    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Bellatrix => {
                LightClientHeaderBellatrix::from_ssz_bytes(bytes).map(Self::Bellatrix)
            }
            ForkName::Capella => LightClientHeaderCapella::from_ssz_bytes(bytes).map(Self::Capella),
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
    fn serde_light_client_header_bellatrix(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/bellatrix/LightClientHeader/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: LightClientHeaderBellatrix = serde_json::from_value(value.clone()).unwrap();
        let serialized = serde_json::to_value(content).unwrap();
        assert_eq!(serialized, value);
    }

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    #[case("case_2")]
    #[case("case_3")]
    #[case("case_4")]
    fn ssz_light_client_header_bellatrix(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/bellatrix/LightClientHeader/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: LightClientHeaderBellatrix = serde_json::from_value(value).unwrap();

        let compressed = std::fs::read(format!(
            "../test_assets/beacon/bellatrix/LightClientHeader/ssz_random/{case}/serialized.ssz_snappy"
        ))
            .expect("cannot find test asset");
        let mut decoder = snap::raw::Decoder::new();
        let expected = decoder.decompress_vec(&compressed).unwrap();
        LightClientHeader::from_ssz_bytes(&expected, ForkName::Bellatrix).unwrap();
        assert_eq!(content.as_ssz_bytes(), expected);
    }

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    #[case("case_2")]
    #[case("case_3")]
    #[case("case_4")]
    fn serde_light_client_header_capella(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/capella/LightClientHeader/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: LightClientHeaderCapella = serde_json::from_value(value.clone()).unwrap();
        let serialized = serde_json::to_value(content).unwrap();
        assert_eq!(serialized, value);
    }

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    #[case("case_2")]
    #[case("case_3")]
    #[case("case_4")]
    fn ssz_light_client_header_capella(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/capella/LightClientHeader/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: LightClientHeaderCapella = serde_json::from_value(value).unwrap();

        let compressed = std::fs::read(format!(
            "../test_assets/beacon/capella/LightClientHeader/ssz_random/{case}/serialized.ssz_snappy"
        ))
            .expect("cannot find test asset");
        let mut decoder = snap::raw::Decoder::new();
        let expected = decoder.decompress_vec(&compressed).unwrap();
        LightClientHeader::from_ssz_bytes(&expected, ForkName::Capella).unwrap();
        assert_eq!(content.as_ssz_bytes(), expected);
    }
}
