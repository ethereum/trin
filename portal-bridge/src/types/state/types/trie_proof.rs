use ethportal_api::types::state_trie::{EncodedTrieNode, TrieProof as EncodedTrieProof};
use revm_primitives::Bytes;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrieProof {
    pub path: Vec<u8>,
    pub proof: Vec<Bytes>,
}

impl From<&TrieProof> for EncodedTrieProof {
    fn from(trie_proof: &TrieProof) -> Self {
        EncodedTrieProof::from(
            trie_proof
                .proof
                .iter()
                .map(|bytes| EncodedTrieNode::from(bytes.to_vec()))
                .collect::<Vec<EncodedTrieNode>>(),
        )
    }
}
