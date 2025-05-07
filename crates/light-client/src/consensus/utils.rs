use alloy::primitives::{FixedBytes, B256};
use anyhow::Result;
use ethportal_api::consensus::{header::BeaconBlockHeader, signature::BlsSignature};
use milagro_bls::{AggregateSignature, PublicKey};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;
use trin_validation::merkle::proof::merkle_root_from_branch;

use crate::utils::compute_fork_data_root;

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
    branch: &[B256],
    depth: usize,
    index: usize,
) -> bool {
    let leaf_hash = leaf_object.tree_hash_root();
    let state_root = attested_header.state_root;

    let root = merkle_root_from_branch(leaf_hash, branch, depth, index);

    root == state_root
}

#[derive(Default, Debug, TreeHash)]
struct SigningData {
    object_root: B256,
    domain: B256,
}

pub fn compute_signing_root(object_root: B256, domain: B256) -> B256 {
    let data = SigningData {
        object_root,
        domain,
    };
    data.tree_hash_root()
}

pub fn compute_domain(
    domain_type: FixedBytes<4>,
    fork_version: FixedBytes<4>,
    genesis_root: B256,
) -> Result<B256> {
    let fork_data_root = compute_fork_data_root(fork_version, genesis_root);
    let end = &fork_data_root.as_slice()[..28];
    let domain = [&*domain_type, end].concat();
    Ok(B256::from_slice(&domain))
}
