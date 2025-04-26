use alloy::primitives::B256;
use rs_merkle::{algorithms::Sha256, MerkleTree};

pub fn build_merkle_proof_for_index<T: Into<[u8; 32]>>(
    leaves: impl IntoIterator<Item = T, IntoIter: ExactSizeIterator>,
    index_to_prove: usize,
) -> Vec<B256> {
    let leaves = leaves.into_iter();
    // Returns the smallest power of two greater than or equal to self
    let full_tree_len = leaves.len().next_power_of_two();

    // Convert to [u8;32], and append [0;32] until we have full_tree_len
    let leaves = leaves
        .map(Into::into)
        .chain(std::iter::repeat([0; 32]))
        .take(full_tree_len)
        .collect::<Vec<_>>();

    let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    let indices_to_prove = vec![index_to_prove];
    let proof = merkle_tree.proof(&indices_to_prove);
    proof
        .proof_hashes()
        .iter()
        .map(|hash| B256::from_slice(hash))
        .collect()
}
