use alloy::primitives::B256;
use rs_merkle::{algorithms::Sha256, MerkleTree};

pub fn build_merkle_proof_for_index(mut leaves: Vec<[u8; 32]>, index_to_prove: usize) -> Vec<B256> {
    // Returns the smallest power of two greater than or equal to self
    let full_tree_len = leaves.len().next_power_of_two();
    // We want to add empty leaves to make the tree a power of 2
    while leaves.len() < full_tree_len {
        leaves.push([0; 32]);
    }

    let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    let indices_to_prove = vec![index_to_prove];
    let proof = merkle_tree.proof(&indices_to_prove);
    proof
        .proof_hashes()
        .iter()
        .map(|hash| B256::from_slice(hash))
        .collect()
}
