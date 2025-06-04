use std::sync::Arc;

use alloy::primitives::{keccak256, B256};
use eth_trie::DB;
use redb::{Database as ReDB, TableDefinition};

use super::error::EVMError;

static NULL_RLP_STATIC: [u8; 1] = [0x80; 1];

const ACCOUNT_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("account_storage");

#[derive(Debug, Clone)]
pub struct AccountDB {
    pub address_hash: B256,
    pub db: Arc<ReDB>,
}

impl From<redb::Error> for EVMError {
    fn from(e: redb::Error) -> Self {
        EVMError::DB(Box::new(e))
    }
}

impl AccountDB {
    pub fn new(address_hash: B256, db: Arc<ReDB>) -> Result<Self, EVMError> {
        let txn = db.begin_write().map_err(EVMError::from)?;
        txn.open_table(ACCOUNT_TABLE).map_err(EVMError::from)?;
        txn.commit().map_err(EVMError::from)?;

        Ok(Self { address_hash, db })
    }

    pub fn get_db_key(&self, key: &[u8]) -> Vec<u8> {
        [self.address_hash.as_slice(), key].concat()
    }
}

impl DB for AccountDB {
    type Error = EVMError;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        if B256::from_slice(key) == keccak256([]) {
            return Ok(Some(NULL_RLP_STATIC.to_vec()));
        }

        let txn = self.db.begin_read().map_err(EVMError::from)?;
        let table = txn.open_table(ACCOUNT_TABLE).map_err(EVMError::from)?;
        let db_key = self.get_db_key(key);

        match table.get(db_key.as_slice()).map_err(EVMError::from)? {
            Some(access_guard) => Ok(Some(access_guard.value().to_vec())),
            None => Ok(None),
        }
    }

    fn insert(&self, key: &[u8], value: Vec<u8>) -> Result<(), Self::Error> {
        if B256::from_slice(key) == keccak256([]) {
            return Ok(());
        }

        let txn = self.db.begin_write().map_err(EVMError::from)?;
        {
            let mut table = txn.open_table(ACCOUNT_TABLE).map_err(EVMError::from)?;
            let db_key = self.get_db_key(key);
            table
                .insert(db_key.as_slice(), value.as_slice())
                .map_err(EVMError::from)?;
        }
        txn.commit().map_err(EVMError::from)?;
        Ok(())
    }

    fn remove(&self, key: &[u8]) -> Result<(), Self::Error> {
        if B256::from_slice(key) == keccak256([]) {
            return Ok(());
        }

        let txn = self.db.begin_write().map_err(EVMError::from)?;
        {
            let mut table = txn.open_table(ACCOUNT_TABLE).map_err(EVMError::from)?;
            let db_key = self.get_db_key(key);
            table.remove(db_key.as_slice()).map_err(EVMError::from)?;
        }
        txn.commit().map_err(EVMError::from)?;
        Ok(())
    }

    fn flush(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}
