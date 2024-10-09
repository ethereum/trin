use std::sync::Arc;

use alloy::{primitives::B256, rlp::Encodable};
use anyhow::anyhow;
use eth_trie::{EthTrie, MemoryDB, Trie};

/// Calculate the Merkle Patricia Trie root hash from a list of items
///
/// `(rlp(index), encoded(item))` pairs.
pub fn calculate_merkle_patricia_root<'a, T: Encodable + 'a>(
    items: impl IntoIterator<Item = &'a T>,
) -> anyhow::Result<B256> {
    let memdb = Arc::new(MemoryDB::new(true));
    let mut trie = EthTrie::new(memdb);

    // Insert items into merkle patricia trie
    for (index, tx) in items.into_iter().enumerate() {
        let path = alloy::rlp::encode(index);
        let encoded_tx = alloy::rlp::encode(tx);
        trie.insert(&path, &encoded_tx)
            .map_err(|err| anyhow!("Error inserting into merkle patricia trie: {err:?}"))?;
    }

    trie.root_hash()
        .map_err(|err| anyhow!("Error calculating merkle patricia trie root: {err:?}"))
}
