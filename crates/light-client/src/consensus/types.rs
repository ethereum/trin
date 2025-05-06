use alloy::primitives::B256;
use anyhow::Result;
use ethportal_api::{
    consensus::header::BeaconBlockHeader,
    light_client::{
        bootstrap::CurrentSyncCommitteeProofLenElectra, update::FinalizedRootProofLenElectra,
    },
};
pub use ethportal_api::{
    consensus::{body::SyncAggregate, sync_committee::SyncCommittee},
    light_client::{
        bootstrap::LightClientBootstrapElectra, finality_update::LightClientFinalityUpdateElectra,
        header::LightClientHeaderElectra, optimistic_update::LightClientOptimisticUpdateElectra,
        update::LightClientUpdateElectra,
    },
};
use ssz_types::FixedVector;

#[derive(Debug, Clone)]
pub struct GenericUpdate {
    pub attested_header: BeaconBlockHeader,
    pub sync_aggregate: SyncAggregate,
    pub signature_slot: u64,
    pub next_sync_committee: Option<SyncCommittee>,
    pub next_sync_committee_branch: Option<FixedVector<B256, CurrentSyncCommitteeProofLenElectra>>,
    pub finalized_header: Option<BeaconBlockHeader>,
    pub finality_branch: Option<FixedVector<B256, FinalizedRootProofLenElectra>>,
}

impl From<&LightClientUpdateElectra> for GenericUpdate {
    fn from(update: &LightClientUpdateElectra) -> Self {
        Self {
            attested_header: update.attested_header.beacon.clone(),
            sync_aggregate: update.sync_aggregate.clone(),
            signature_slot: update.signature_slot,
            next_sync_committee: Some(update.next_sync_committee.clone()),
            next_sync_committee_branch: Some(update.next_sync_committee_branch.clone()),
            finalized_header: Some(update.finalized_header.beacon.clone()),
            finality_branch: Some(update.finality_branch.clone()),
        }
    }
}

impl From<&LightClientFinalityUpdateElectra> for GenericUpdate {
    fn from(update: &LightClientFinalityUpdateElectra) -> Self {
        Self {
            attested_header: update.attested_header.beacon.clone(),
            sync_aggregate: update.sync_aggregate.clone(),
            signature_slot: update.signature_slot,
            next_sync_committee: None,
            next_sync_committee_branch: None,
            finalized_header: Some(update.finalized_header.beacon.clone()),
            finality_branch: Some(update.finality_branch.clone()),
        }
    }
}

impl From<&LightClientOptimisticUpdateElectra> for GenericUpdate {
    fn from(update: &LightClientOptimisticUpdateElectra) -> Self {
        Self {
            attested_header: update.attested_header.beacon.clone(),
            sync_aggregate: update.sync_aggregate.clone(),
            signature_slot: update.signature_slot,
            next_sync_committee: None,
            next_sync_committee_branch: None,
            finalized_header: None,
            finality_branch: None,
        }
    }
}

pub fn u64_deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{Error, Unexpected};

    let val: String = serde::Deserialize::deserialize(deserializer)?;
    val.parse()
        .map_err(|_| Error::invalid_value(Unexpected::Str(&val), &"valid u64"))
}
