use serde::{Deserialize, Serialize};
use serde_this_or_that::as_u64;
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

use crate::{
    light_client::header::LightClientHeaderDeneb,
    types::consensus::{
        body::SyncAggregate,
        fork::ForkName,
        light_client::header::{LightClientHeaderBellatrix, LightClientHeaderCapella},
    },
};

/// A LightClientOptimisticUpdate is the update we receive on each slot,
/// it is based off the current unfinalized epoch and it is verified only against BLS signature.
#[superstruct(
    variants(Bellatrix, Capella, Deneb),
    variant_attributes(
        derive(
            Debug,
            Clone,
            PartialEq,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash
        ),
        serde(deny_unknown_fields),
    )
)]
#[derive(Debug, Clone, Serialize, PartialEq, Deserialize, Encode)]
#[ssz(enum_behaviour = "transparent")]
pub struct LightClientOptimisticUpdate {
    /// The last `LightClientHeader` from the last attested block by the sync committee.
    #[superstruct(only(Bellatrix), partial_getter(rename = "attested_header_bellatrix"))]
    pub attested_header: LightClientHeaderBellatrix,
    #[superstruct(only(Capella), partial_getter(rename = "attested_header_capella"))]
    pub attested_header: LightClientHeaderCapella,
    #[superstruct(only(Deneb), partial_getter(rename = "attested_header_deneb"))]
    pub attested_header: LightClientHeaderDeneb,
    /// current sync aggregate
    pub sync_aggregate: SyncAggregate,
    /// Slot of the sync aggregated signature
    #[serde(deserialize_with = "as_u64")]
    pub signature_slot: u64,
}

impl LightClientOptimisticUpdate {
    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Bellatrix => {
                LightClientOptimisticUpdateBellatrix::from_ssz_bytes(bytes).map(Self::Bellatrix)
            }
            ForkName::Capella => {
                LightClientOptimisticUpdateCapella::from_ssz_bytes(bytes).map(Self::Capella)
            }
            ForkName::Deneb => {
                LightClientOptimisticUpdateDeneb::from_ssz_bytes(bytes).map(Self::Deneb)
            }
        }
    }
}
