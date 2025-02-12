use alloy::{
    consensus::{
        proofs::{ordered_trie_root, ordered_trie_root_with_encoder},
        EMPTY_OMMER_ROOT_HASH,
    },
    primitives::{keccak256, B256},
    rlp::Encodable,
};

use crate::types::execution::withdrawal::Withdrawal;

/// Calculate the Merkle Patricia Trie root hash from a list of items

/// `(rlp(index), encoded(item))` pairs.
pub fn calculate_merkle_patricia_root<T>(transactions: &[T]) -> B256
where
    T: Encodable,
{
    ordered_trie_root_with_encoder(transactions, |tx: &T, buf| tx.encode(buf))
}

/// Calculates the root hash of the withdrawals.
pub fn calculate_withdrawals_root(withdrawals: &[Withdrawal]) -> B256 {
    ordered_trie_root(withdrawals)
}

/// Calculates the root hash for ommer/uncle headers.
///
/// See [`Header`](crate::Header).
pub fn calculate_ommers_root<T>(ommers: &[T]) -> B256
where
    T: Encodable,
{
    // Check if `ommers` list is empty
    if ommers.is_empty() {
        return EMPTY_OMMER_ROOT_HASH;
    }
    // RLP Encode
    let mut ommers_rlp = Vec::new();
    alloy_rlp::encode_list(ommers, &mut ommers_rlp);
    keccak256(ommers_rlp)
}
