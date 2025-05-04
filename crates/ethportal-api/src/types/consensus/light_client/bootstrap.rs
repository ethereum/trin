use alloy::primitives::B256;
use serde::{Deserialize, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::{
    typenum::{U5, U6},
    FixedVector,
};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

use crate::{
    consensus::header::BeaconBlockHeader,
    light_client::header::{LightClientHeaderDeneb, LightClientHeaderElectra},
    types::consensus::{
        fork::ForkName,
        light_client::header::{LightClientHeaderBellatrix, LightClientHeaderCapella},
        sync_committee::SyncCommittee,
    },
};

pub type CurrentSyncCommitteeProofLen = U5;
pub type CurrentSyncCommitteeProofLenElectra = U6;

/// `LightClientBootstrap` object for the configured trusted block root.
/// The bootstrap object is used to generate a local `LightClientStore`.
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
#[serde(untagged)]
#[ssz(enum_behaviour = "transparent")]
pub struct LightClientBootstrap {
    /// Header matching the requested beacon block root
    #[superstruct(only(Bellatrix), partial_getter(rename = "header_bellatrix"))]
    pub header: LightClientHeaderBellatrix,
    #[superstruct(only(Capella), partial_getter(rename = "header_capella"))]
    pub header: LightClientHeaderCapella,
    #[superstruct(only(Deneb), partial_getter(rename = "header_deneb"))]
    pub header: LightClientHeaderDeneb,
    #[superstruct(only(Electra), partial_getter(rename = "header_electra"))]
    pub header: LightClientHeaderElectra,
    /// Current sync committee corresponding to `header.beacon.state_root`
    pub current_sync_committee: SyncCommittee,
    #[superstruct(
        only(Bellatrix, Capella, Deneb),
        partial_getter(rename = "current_sync_committee_branch_base")
    )]
    pub current_sync_committee_branch: FixedVector<B256, CurrentSyncCommitteeProofLen>,
    #[superstruct(
        only(Electra),
        partial_getter(rename = "current_sync_committee_branch_electra")
    )]
    pub current_sync_committee_branch: FixedVector<B256, CurrentSyncCommitteeProofLenElectra>,
}

impl LightClientBootstrap {
    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Bellatrix => {
                LightClientBootstrapBellatrix::from_ssz_bytes(bytes).map(Self::Bellatrix)
            }
            ForkName::Capella => {
                LightClientBootstrapCapella::from_ssz_bytes(bytes).map(Self::Capella)
            }
            ForkName::Deneb => LightClientBootstrapDeneb::from_ssz_bytes(bytes).map(Self::Deneb),
            ForkName::Electra => {
                LightClientBootstrapElectra::from_ssz_bytes(bytes).map(Self::Electra)
            }
        }
    }

    /// Returns the `BeaconBlockHeader` from the `LightClientBootstrap` object.
    pub fn get_beacon_block_header(&self) -> &BeaconBlockHeader {
        match self {
            Self::Bellatrix(bootstrap) => &bootstrap.header.beacon,
            Self::Capella(bootstrap) => &bootstrap.header.beacon,
            Self::Deneb(bootstrap) => &bootstrap.header.beacon,
            Self::Electra(bootstrap) => &bootstrap.header.beacon,
        }
    }
}
