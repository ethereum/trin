use alloy::primitives::B256;
use serde::{Deserialize, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum::U5, FixedVector};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

use crate::{
    consensus::header::BeaconBlockHeader,
    light_client::header::LightClientHeaderDeneb,
    types::consensus::{
        fork::ForkName,
        light_client::header::{LightClientHeaderBellatrix, LightClientHeaderCapella},
        sync_committee::SyncCommittee,
    },
};

pub type CurrentSyncCommitteeProofLen = U5;

/// `LightClientBootstrap` object for the configured trusted block root.
/// The bootstrap object is used to generate a local `LightClientStore`.
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
    /// Current sync committee corresponding to `header.beacon.state_root`
    pub current_sync_committee: SyncCommittee,
    pub current_sync_committee_branch: FixedVector<B256, CurrentSyncCommitteeProofLen>,
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
        }
    }

    /// Returns the `BeaconBlockHeader` from the `LightClientBootstrap` object.
    pub fn get_beacon_block_header(self) -> BeaconBlockHeader {
        match self {
            LightClientBootstrap::Bellatrix(bootstrap) => bootstrap.header.beacon,
            LightClientBootstrap::Capella(bootstrap) => bootstrap.header.beacon,
            LightClientBootstrap::Deneb(bootstrap) => bootstrap.header.beacon,
        }
    }
}
