use alloy::primitives::B256;
use anyhow::Result;
use ethportal_api::consensus::{header::BeaconBlockHeader, signature::BlsSignature};
use milagro_bls::{AggregateSignature, PublicKey};
use ssz::Encode;
use ssz_types::{typenum::U4, FixedVector};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;
use trin_validation::merkle::proof::merkle_root_from_branch;

use crate::{types::Bytes32, utils::bytes32_to_node};

pub fn calc_sync_period(slot: u64) -> u64 {
    let epoch = slot / 32; // 32 slots per epoch
    epoch / 256 // 256 epochs per sync committee
}

pub fn is_aggregate_valid(sig_bytes: &BlsSignature, msg: &[u8], pks: &[&PublicKey]) -> bool {
    let sig_res = AggregateSignature::from_bytes(&sig_bytes.signature);
    match sig_res {
        Ok(sig) => sig.fast_aggregate_verify(msg, pks),
        Err(_) => false,
    }
}

pub fn is_proof_valid<L: TreeHash>(
    attested_header: &BeaconBlockHeader,
    leaf_object: &L,
    branch: &[Bytes32],
    depth: usize,
    index: usize,
) -> bool {
    let res: Result<bool> = (move || {
        let leaf_hash = leaf_object.tree_hash_root();
        let state_root = bytes32_to_node(&Bytes32::from(attested_header.state_root.0.to_vec()))?;
        let branches = branch_to_nodes(branch.to_vec())?;

        leaf_hash.ssz_append(&mut branches.as_ssz_bytes());

        let root = merkle_root_from_branch(leaf_hash, &branches, depth, index);

        Ok(root == state_root)
    })();

    res.unwrap_or_default()
}

#[derive(Default, Debug, TreeHash)]
struct SigningData {
    object_root: Bytes32,
    domain: Bytes32,
}

#[derive(Default, Debug, TreeHash)]
struct ForkData {
    current_version: FixedVector<u8, U4>,
    genesis_validator_root: Bytes32,
}

pub fn compute_signing_root(object_root: Bytes32, domain: Bytes32) -> B256 {
    let data = SigningData {
        object_root,
        domain,
    };
    data.tree_hash_root()
}

pub fn compute_domain(
    domain_type: &[u8],
    fork_version: FixedVector<u8, U4>,
    genesis_root: Bytes32,
) -> Result<Bytes32> {
    let fork_data_root = compute_fork_data_root(fork_version, genesis_root);
    let start = domain_type;
    let end = &fork_data_root.as_slice()[..28];
    let d = [start, end].concat();
    Ok(d.to_vec().into())
}

fn compute_fork_data_root(
    current_version: FixedVector<u8, U4>,
    genesis_validator_root: Bytes32,
) -> B256 {
    let fork_data = ForkData {
        current_version,
        genesis_validator_root,
    };
    fork_data.tree_hash_root()
}

pub fn branch_to_nodes(branch: Vec<Bytes32>) -> Result<Vec<B256>> {
    branch
        .iter()
        .map(bytes32_to_node)
        .collect::<Result<Vec<B256>>>()
}
