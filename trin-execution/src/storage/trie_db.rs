use std::sync::Arc;

use eth_trie::DB;
use rocksdb::DB as RocksDB;

#[derive(Debug)]
pub struct TrieRocksDB {
    // If "light" is true, the data is deleted from the database at the time of submission.
    light: bool,
    storage: Arc<RocksDB>,
}

impl TrieRocksDB {
    pub fn new(light: bool, storage: Arc<RocksDB>) -> Self {
        TrieRocksDB { light, storage }
    }
}

impl DB for TrieRocksDB {
    type Error = rocksdb::Error;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        self.storage.get(key)
    }

    fn insert(&self, key: &[u8], value: Vec<u8>) -> Result<(), Self::Error> {
        self.storage.put(key, value)
    }

    fn remove(&self, key: &[u8]) -> Result<(), Self::Error> {
        if self.light {
            self.storage.delete(key)?;
        }
        Ok(())
    }

    fn flush(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}
