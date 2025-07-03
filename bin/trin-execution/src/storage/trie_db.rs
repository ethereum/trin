use std::sync::Arc;

use eth_trie::DB;
use redb::{Database as ReDB, TableDefinition};

// Define a table type: key and value are byte arrays
const TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("trie");

#[derive(Debug)]
pub struct TrieReDB {
    // If "light" is true, the data is deleted from the database at the time of submission.
    light: bool,
    storage: Arc<ReDB>,
}

impl TrieReDB {
    pub fn new(light: bool, storage: Arc<ReDB>) -> Self {
        TrieReDB { light, storage }
    }
}

impl DB for TrieReDB {
    type Error = redb::Error;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        let txn = self.storage.begin_read()?;
        let table = txn.open_table(TABLE)?;
        Ok(table.get(key)?.map(|val| val.value().to_vec()))
    }

    fn insert(&self, key: &[u8], value: Vec<u8>) -> Result<(), Self::Error> {
        let txn = self.storage.begin_write()?;
        {
            let mut table = txn.open_table(TABLE)?;
            table.insert(key, value.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    fn remove(&self, key: &[u8]) -> Result<(), Self::Error> {
        if self.light {
            let txn = self.storage.begin_write()?;
            {
                let mut table = txn.open_table(TABLE)?;
                table.remove(key)?;
            }
            txn.commit()?;
        }
        Ok(())
    }

    fn flush(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}
