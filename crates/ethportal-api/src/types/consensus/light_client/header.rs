use alloy::primitives::B256;
use serde::{Deserialize, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum::U4, FixedVector};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

use crate::{
    consensus::execution_payload::{ExecutionPayloadHeaderDeneb, ExecutionPayloadHeaderElectra},
    types::consensus::{
        execution_payload::ExecutionPayloadHeaderCapella, fork::ForkName, header::BeaconBlockHeader,
    },
};

pub type ExecutionBranchLen = U4;

#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra),
    variant_attributes(
        derive(
            Debug,
            Clone,
            Serialize,
            PartialEq,
            Deserialize,
            Encode,
            Decode,
            Default,
            TreeHash
        ),
        serde(deny_unknown_fields),
    )
)]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, TreeHash)]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct LightClientHeader {
    pub beacon: BeaconBlockHeader,
    #[superstruct(only(Capella), partial_getter(rename = "execution_capella"))]
    pub execution: ExecutionPayloadHeaderCapella,
    #[superstruct(only(Deneb), partial_getter(rename = "execution_deneb"))]
    pub execution: ExecutionPayloadHeaderDeneb,
    #[superstruct(only(Electra), partial_getter(rename = "execution_electra"))]
    pub execution: ExecutionPayloadHeaderElectra,
    #[superstruct(only(Capella, Deneb, Electra))]
    pub execution_branch: FixedVector<B256, ExecutionBranchLen>,
}

impl Default for LightClientHeader {
    fn default() -> Self {
        Self::Capella(LightClientHeaderCapella::default())
    }
}

impl LightClientHeader {
    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Bellatrix => {
                LightClientHeaderBellatrix::from_ssz_bytes(bytes).map(Self::Bellatrix)
            }
            ForkName::Capella => LightClientHeaderCapella::from_ssz_bytes(bytes).map(Self::Capella),
            ForkName::Deneb => LightClientHeaderDeneb::from_ssz_bytes(bytes).map(Self::Deneb),
            ForkName::Electra => LightClientHeaderElectra::from_ssz_bytes(bytes).map(Self::Electra),
        }
    }
}
