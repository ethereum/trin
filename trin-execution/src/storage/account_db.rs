use std::sync::Arc;

use alloy_primitives::{keccak256, Address, B256};
use eth_trie::DB;
use rocksdb::DB as RocksDB;

use super::error::EVMError;

static NULL_RLP_STATIC: [u8; 1] = [0x80; 1];

#[derive(Debug, Clone)]
pub struct AccountDB {
    pub address_hash: B256,
    /// storage trie
    pub db: Arc<RocksDB>,
}

impl AccountDB {
    pub fn new(address: Address, db: Arc<RocksDB>) -> Self {
        Self {
            address_hash: keccak256(address),
            db,
        }
    }

    fn get_db_key(&self, key: &[u8]) -> Vec<u8> {
        [self.address_hash.as_slice(), key].concat()
    }
}

impl DB for AccountDB {
    type Error = EVMError;
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, EVMError> {
        if B256::from_slice(key) == keccak256([]) {
            return Ok(Some(NULL_RLP_STATIC.to_vec()));
        }

        self.db.get(self.get_db_key(key)).map_err(|err| err.into())
    }

    fn insert(&self, key: &[u8], value: Vec<u8>) -> Result<(), EVMError> {
        if B256::from_slice(key) == keccak256([]) {
            return Ok(());
        }
        self.db
            .put(self.get_db_key(key), value)
            .map_err(|err| err.into())
    }

    fn remove(&self, key: &[u8]) -> Result<(), EVMError> {
        if B256::from_slice(key) == keccak256([]) {
            return Ok(());
        }
        self.db
            .delete(self.get_db_key(key))
            .map_err(|err| err.into())
    }

    fn flush(&self) -> Result<(), EVMError> {
        self.db.flush().map_err(|err| err.into())
    }
}

#[cfg(test)]
mod test_account_db {

    use crate::storage::utils::{setup_rocksdb, setup_temp_dir};

    use super::*;
    use eth_trie::DB;

    #[test]
    fn test_account_db_get() {
        let rocksdb = setup_rocksdb(setup_temp_dir().unwrap().into_path()).unwrap();
        let accdb = AccountDB::new(Address::ZERO, Arc::new(rocksdb));
        accdb
            .insert(keccak256(b"test-key").as_slice(), b"test-value".to_vec())
            .unwrap();
        let v = accdb
            .get(keccak256(b"test-key").as_slice())
            .unwrap()
            .unwrap();
        assert_eq!(v, b"test-value")
    }

    #[test]
    fn test_account_db_remove() {
        let rocksdb = setup_rocksdb(setup_temp_dir().unwrap().into_path()).unwrap();
        let accdb = AccountDB::new(Address::ZERO, Arc::new(rocksdb));
        accdb
            .insert(keccak256(b"test").as_slice(), b"test".to_vec())
            .unwrap();
        accdb.remove(keccak256(b"test").as_slice()).unwrap();
        let contains = accdb.get(keccak256(b"test").as_slice()).unwrap();
        assert_eq!(contains, None)
    }
}
