use std::sync::Arc;

use anyhow::anyhow;
use eth_trie::DB;
use hashbrown::HashMap;
use parking_lot::Mutex;
use revm_primitives::B256;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReadOnlyMemoryDBError {
    #[error("read only memory db error {0}")]
    ANYHOW(#[from] anyhow::Error),
}

#[derive(Debug)]
pub struct ReadOnlyMemoryDB {
    storage: Arc<Mutex<HashMap<B256, Vec<u8>>>>,
}

impl ReadOnlyMemoryDB {
    pub fn new(storage: HashMap<B256, Vec<u8>>) -> Self {
        ReadOnlyMemoryDB {
            storage: Arc::new(Mutex::new(storage)),
        }
    }
}

impl DB for ReadOnlyMemoryDB {
    type Error = ReadOnlyMemoryDBError;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.storage.lock().get(key).cloned())
    }

    fn insert(&self, _key: &[u8], _value: Vec<u8>) -> Result<(), Self::Error> {
        Err(anyhow!("Cannot insert into read only memory db").into())
    }

    fn remove(&self, _key: &[u8]) -> Result<(), Self::Error> {
        Err(anyhow!("Cannot remove from read only memory db").into())
    }

    fn flush(&self) -> Result<(), Self::Error> {
        Err(anyhow!("Cannot flush read only memory db").into())
    }
}
