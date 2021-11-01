use std::sync::Arc;

pub struct TrieDB {
    db: Arc<rocksdb::DB>,
}

impl TrieDB {
    pub fn new(db: Arc<rocksdb::DB>) -> TrieDB {
        TrieDB { db }
    }
}

impl eth_trie::DB for TrieDB {
    type Error = rocksdb::Error;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        self.db.get(key)
    }

    fn insert(&self, key: &[u8], value: Vec<u8>) -> Result<(), Self::Error> {
        self.db.put(key, value)
    }

    fn remove(&self, key: &[u8]) -> Result<(), Self::Error> {
        self.db.delete(key)
    }

    fn flush(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}
