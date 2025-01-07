use alloy::primitives::B256;
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_u64;
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::{
    typenum::{U5, U6},
    FixedVector,
};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

use crate::{
    light_client::header::LightClientHeaderDeneb,
    types::consensus::{
        body::SyncAggregate,
        fork::ForkName,
        light_client::header::{LightClientHeaderBellatrix, LightClientHeaderCapella},
        sync_committee::SyncCommittee,
    },
};

type NextSyncCommitteeProofLen = U5;
pub type FinalizedRootProofLen = U6;

#[superstruct(
    variants(Bellatrix, Capella, Deneb),
    variant_attributes(
        derive(
            Debug,
            Clone,
            Serialize,
            PartialEq,
            Deserialize,
            Encode,
            Decode,
            TreeHash
        ),
        serde(deny_unknown_fields),
    )
)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode)]
#[ssz(enum_behaviour = "transparent")]
pub struct LightClientUpdate {
    /// The last `LightClientHeader` from the last attested block by the sync committee.
    #[superstruct(only(Bellatrix), partial_getter(rename = "attested_header_bellatrix"))]
    pub attested_header: LightClientHeaderBellatrix,
    #[superstruct(only(Capella), partial_getter(rename = "attested_header_capella"))]
    pub attested_header: LightClientHeaderCapella,
    #[superstruct(only(Deneb), partial_getter(rename = "attested_header_deneb"))]
    pub attested_header: LightClientHeaderDeneb,
    /// The `SyncCommittee` used in the next period.
    pub next_sync_committee: SyncCommittee,
    /// Merkle proof for next sync committee
    pub next_sync_committee_branch: FixedVector<B256, NextSyncCommitteeProofLen>,
    /// The last `LightClientHeader` from the last attested finalized block (end of epoch).
    #[superstruct(only(Bellatrix), partial_getter(rename = "finalized_header_bellatrix"))]
    pub finalized_header: LightClientHeaderBellatrix,
    #[superstruct(only(Capella), partial_getter(rename = "finalized_header_capella"))]
    pub finalized_header: LightClientHeaderCapella,
    #[superstruct(only(Deneb), partial_getter(rename = "finalized_header_deneb"))]
    pub finalized_header: LightClientHeaderDeneb,
    /// Merkle proof attesting finalized header.
    pub finality_branch: FixedVector<B256, FinalizedRootProofLen>,
    /// current sync aggregate
    pub sync_aggregate: SyncAggregate,
    /// Slot of the sync aggregated signature
    #[serde(deserialize_with = "as_u64")]
    pub signature_slot: u64,
}

impl LightClientUpdate {
    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Bellatrix => {
                LightClientUpdateBellatrix::from_ssz_bytes(bytes).map(Self::Bellatrix)
            }
            ForkName::Capella => LightClientUpdateCapella::from_ssz_bytes(bytes).map(Self::Capella),
            ForkName::Deneb => LightClientUpdateDeneb::from_ssz_bytes(bytes).map(Self::Deneb),
        }
    }
}
