use ethereum_types::H256;
use ssz_types::{typenum, VariableList};

/// Types sourced from Fluffy:
/// https://github.com/status-im/nimbus-eth1/blob/77135e70015de77d9ca46b196d99dc260ed3e364/fluffy/network/history/experimental/beacon_chain_block_proof.nim

// uint64(2**13) (= 8,192)
const _SLOTS_PER_HISTORICAL_ROOT: u64 = 8_192;

// uint64(2**24) (= 16,777,216)
const _HISTORICAL_ROOTS_LIMIT: u64 = 16_777_216;

//BeaconBlockBodyProof* = array[8, Digest]
pub struct BeaconBlockBodyProof([H256; 8]);

//BeaconBlockHeaderProof* = array[3, Digest]
pub struct BeaconBlockHeaderProof([H256; 3]);

//HistoricalRootsProof* = array[14, Digest]
pub struct BeaconBlockHistoricalRootsProof([H256; 14]);

//# Total size (8 + 1 + 3 + 1 + 14) * 32 bytes + 4 bytes = 868 bytes
pub struct BeaconChainBlockProof {
    pub beacon_block_body_proof: BeaconBlockBodyProof,
    pub beacon_block_body_root: H256,
    pub beacon_block_header_proof: BeaconBlockHeaderProof,
    pub beacon_block_header_root: H256,
    pub historical_roots_proof: BeaconBlockHistoricalRootsProof,
    pub slot: u64,
}

#[derive(Debug, PartialEq, Clone, Default)]
pub struct HistoricalRoots(VariableList<tree_hash::Hash256, typenum::U16777216>);

pub struct HistoricalRootsProof([H256; 5]);

pub struct HistoricalRootsWithProof {
    pub historical_roots: HistoricalRoots,
    pub proof: HistoricalRootsProof,
}
