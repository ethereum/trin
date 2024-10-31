use alloy::primitives::{Bytes, B256};
use anyhow::anyhow;
use eth_trie::DB;
use hashbrown::HashMap;

use crate::storage::trie_db::TrieRocksDB;

pub trait TrieWalkerDb {
    fn get(&self, key: &[u8]) -> anyhow::Result<Option<Bytes>>;
}

impl TrieWalkerDb for HashMap<B256, Vec<u8>> {
    fn get(&self, key: &[u8]) -> anyhow::Result<Option<Bytes>> {
        Ok(self.get(key).map(|vec| Bytes::copy_from_slice(vec)))
    }
}

impl TrieWalkerDb for TrieRocksDB {
    fn get(&self, key: &[u8]) -> anyhow::Result<Option<Bytes>> {
        DB::get(self, key)
            .map(|result| result.map(Bytes::from))
            .map_err(|err| anyhow!("Failed to read key value from TrieRocksDB {err}"))
    }
}
