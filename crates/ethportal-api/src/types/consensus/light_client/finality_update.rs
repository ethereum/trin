use alloy::primitives::B256;
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_u64;
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum::U7, FixedVector};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

use crate::{
    consensus::header::BeaconBlockHeader,
    light_client::header::{LightClientHeaderDeneb, LightClientHeaderElectra},
    types::consensus::{
        body::SyncAggregate,
        fork::ForkName,
        light_client::{
            header::{LightClientHeaderBellatrix, LightClientHeaderCapella},
            update::FinalizedRootProofLen,
        },
    },
};

type FinalizedRootProofLenElectra = U7;

/// A LightClientFinalityUpdate is the update that
/// signal a new finalized beacon block header for the light client sync protocol.
#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra),
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode)]
#[ssz(enum_behaviour = "transparent")]
pub struct LightClientFinalityUpdate {
    /// The last `LightClientHeader` from the last attested block by the sync committee.
    #[superstruct(only(Bellatrix), partial_getter(rename = "attested_header_bellatrix"))]
    pub attested_header: LightClientHeaderBellatrix,
    #[superstruct(only(Capella), partial_getter(rename = "attested_header_capella"))]
    pub attested_header: LightClientHeaderCapella,
    #[superstruct(only(Deneb), partial_getter(rename = "attested_header_deneb"))]
    pub attested_header: LightClientHeaderDeneb,
    #[superstruct(only(Electra), partial_getter(rename = "attested_header_electra"))]
    pub attested_header: LightClientHeaderElectra,
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
    pub finality_branch: FixedVector<B256, FinalizedRootProofLen>,
    #[superstruct(only(Electra), partial_getter(rename = "finality_branch_electra"))]
    pub finality_branch: FixedVector<B256, FinalizedRootProofLenElectra>,
    /// current sync aggregate
    pub sync_aggregate: SyncAggregate,
    /// Slot of the sync aggregated signature
    #[serde(deserialize_with = "as_u64")]
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
            ForkName::Deneb => {
                LightClientFinalityUpdateDeneb::from_ssz_bytes(bytes).map(Self::Deneb)
            }
            ForkName::Electra => {
                LightClientFinalityUpdateElectra::from_ssz_bytes(bytes).map(Self::Electra)
            }
        }
    }

    pub fn finalized_beacon_block_header(&self) -> &BeaconBlockHeader {
        match self {
            Self::Bellatrix(light_client_update) => &light_client_update.finalized_header.beacon,
            Self::Capella(light_client_update) => &light_client_update.finalized_header.beacon,
            Self::Deneb(light_client_update) => &light_client_update.finalized_header.beacon,
            Self::Electra(light_client_update) => &light_client_update.finalized_header.beacon,
        }
    }
}
