use alloy::primitives::{Bytes, B256};
use anyhow::anyhow;
use hashbrown::HashMap;

use crate::storage::trie_db::TrieRocksDB;

pub trait TrieWalkerDb {
    fn get(&self, key: &[u8]) -> anyhow::Result<Option<Bytes>>;
}

impl TrieWalkerDb for HashMap<B256, Vec<u8>> {
    fn get(&self, key: &[u8]) -> anyhow::Result<Option<Bytes>> {
        Ok(self.get(key).cloned().map(|vec| vec.into()))
    }
}

impl TrieWalkerDb for TrieRocksDB {
    fn get(&self, key: &[u8]) -> anyhow::Result<Option<Bytes>> {
        self.storage
            .get(key)
            .map(|result| result.map(|vec| vec.into()))
            .map_err(|err| anyhow!("Failed to read key value from TrieRocksDB {err}"))
    }
}
