use crate::types::consensus::pubkey::PubKey;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::typenum::U512;
use ssz_types::FixedVector;

type SyncCommitteeSize = U512;

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/beacon-chain.md#synccommittee
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SyncCommittee {
    pub pubkeys: FixedVector<PubKey, SyncCommitteeSize>,
    pub aggregate_pubkey: PubKey,
}
