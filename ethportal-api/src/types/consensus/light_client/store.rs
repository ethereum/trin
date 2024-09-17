use crate::consensus::{header::BeaconBlockHeader, sync_committee::SyncCommittee};
use serde::{Deserialize, Serialize};

/// `LightClientStore` object for the light client sync protocol.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct LightClientStore {
    pub finalized_header: BeaconBlockHeader,
    pub current_sync_committee: SyncCommittee,
    pub next_sync_committee: Option<SyncCommittee>,
    pub optimistic_header: BeaconBlockHeader,
    pub previous_max_active_participants: u64,
    pub current_max_active_participants: u64,
}
