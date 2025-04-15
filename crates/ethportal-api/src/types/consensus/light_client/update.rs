use alloy::primitives::B256;
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_u64;
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::{
    typenum::{U5, U6, U7},
    FixedVector,
};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

use crate::{
    light_client::header::{LightClientHeaderDeneb, LightClientHeaderElectra},
    types::consensus::{
        body::SyncAggregate,
        fork::ForkName,
        light_client::header::{LightClientHeaderBellatrix, LightClientHeaderCapella},
        sync_committee::SyncCommittee,
    },
};

type NextSyncCommitteeProofLen = U5;
type NextSyncCommitteeProofLenElectra = U6;
pub type FinalizedRootProofLen = U6;
pub type FinalizedRootProofLenElectra = U7;
type FinalityBranch = FixedVector<B256, FinalizedRootProofLen>;
type FinalityBranchElectra = FixedVector<B256, FinalizedRootProofLenElectra>;

type NextSyncCommitteeBranch = FixedVector<B256, NextSyncCommitteeProofLen>;

type NextSyncCommitteeBranchElectra = FixedVector<B256, NextSyncCommitteeProofLenElectra>;

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
    #[superstruct(only(Electra), partial_getter(rename = "attested_header_electra"))]
    pub attested_header: LightClientHeaderElectra,
    /// The `SyncCommittee` used in the next period.
    pub next_sync_committee: SyncCommittee,
    /// Merkle proof for next sync committee
    #[superstruct(
        only(Bellatrix, Capella, Deneb),
        partial_getter(rename = "next_sync_committee_branch_base")
    )]
    pub next_sync_committee_branch: NextSyncCommitteeBranch,
    #[superstruct(
        only(Electra),
        partial_getter(rename = "next_sync_committee_branch_electra")
    )]
    pub next_sync_committee_branch: NextSyncCommitteeBranchElectra,
    /// The last `LightClientHeader` from the last attested finalized block (end of epoch).
    #[superstruct(only(Bellatrix), partial_getter(rename = "finalized_header_bellatrix"))]
    pub finalized_header: LightClientHeaderBellatrix,
    #[superstruct(only(Capella), partial_getter(rename = "finalized_header_capella"))]
    pub finalized_header: LightClientHeaderCapella,
    #[superstruct(only(Deneb), partial_getter(rename = "finalized_header_deneb"))]
    pub finalized_header: LightClientHeaderDeneb,
    #[superstruct(only(Electra), partial_getter(rename = "finalized_header_electra"))]
    pub finalized_header: LightClientHeaderElectra,
    /// Merkle proof attesting finalized header.
    #[superstruct(
        only(Bellatrix, Capella, Deneb),
        partial_getter(rename = "finality_branch_base")
    )]
    pub finality_branch: FinalityBranch,
    #[superstruct(only(Electra), partial_getter(rename = "finality_branch_electra"))]
    pub finality_branch: FinalityBranchElectra,
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
            ForkName::Electra => LightClientUpdateElectra::from_ssz_bytes(bytes).map(Self::Electra),
        }
    }
}
