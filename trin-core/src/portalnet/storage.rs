#[allow(unused_imports)]
use rocksdb::{Options, DB, Error, perf};
use crate::utils::{get_data_dir, xor_two_values};
use discv5::enr::NodeId;
use rusqlite::{Connection, Result};

use super::{U256};

pub struct PortalStorageConfig {

    pub storage_capacity_kb: u32,
    pub node_id: NodeId,

}

pub struct PortalStorage {

    node_id: NodeId,
    storage_capacity_kb: u32,
    data_radius: U256,
    farthest_key: Option<String>,
    db: DB,
    meta_db: rusqlite::Connection,
    capacity_reached: bool

}

impl PortalStorage {

    pub fn new(config: &PortalStorageConfig) -> Result<Self, String> {

        // Create DB instance
        let data_path = get_data_dir();

        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        let db = DB::open(&db_opts, data_path).unwrap();

        let conn = Connection::open_in_memory().unwrap();

        let storage = Self {
            node_id: config.node_id,
            storage_capacity_kb: config.storage_capacity_kb,
            data_radius: U256::max(),
            db: db,
            farthest_key: None,
            meta_db: conn,
            capacity_reached: false,
            
        };

        Ok(storage)

    }

    pub fn distance_to_key(&self, key: &String) -> U256 {

        let byte_array = xor_two_values(
            key.as_bytes(), &self.node_id.raw().to_vec()
        );

        U256::from(byte_array)

    }

    pub fn should_store(&self, key: &String) -> bool {

        if self.data_radius < U256::max() {
            self.distance_to_key(key) < self.data_radius
        } else {
            true
        }

    }

    // 1.) Don't store data outside the radius.
    // 2.) Store the data, and then if we're at capacity, drop the farthest and find the new farthest.
    // 3.) Initialize or update farthest_key if necessary 
    pub fn store(mut self, key: &String, value: &String) {

        if !self.should_store(key) {
            return;
        }
        
        self.db.put(key, value).expect("Failed to write to DB"); 

        if self.capacity_reached && self.farthest_key.is_some() {
            let key_to_remove = &self.farthest_key;
            self.db.delete(key_to_remove.as_ref().unwrap()).expect("Failed to delete key.");
        }

        match self.farthest_key.as_ref() {
            None => {
                self.farthest_key = Some(key.to_string());
            },
            Some(farthest) => {
                if self.distance_to_key(key) > self.distance_to_key(&farthest) {
                    self.farthest_key = Some(key.clone());
                }
            }
        }
    
    }

    pub fn get(&self, key: &String) -> Result<Option<Vec<u8>>, Error> {

        self.db.get(key)

    }

    pub fn get_current_radius(&self) -> U256 {

        self.data_radius

    }

    pub fn get_total_storage_usage_kb(&self) -> u64 {

        let p: perf::MemoryUsageStats = perf::get_memory_usage_stats(Some(&[&self.db]), None)
                                            .expect("Failed to get memory usage statistics.");

        p.mem_table_total


    }

    pub fn find_farthest(&self) -> Result<(U256, U256), String> {

      Ok((U256::from(1), U256::from(2)))

    }

}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_new() {

        let storage_config = PortalStorageConfig {
            storage_capacity_kb: 100,
            node_id: NodeId::random(),
        };
        let _ = PortalStorage::new(&storage_config);

    }

    #[test]
    fn test_store() {

      let storage_config = PortalStorageConfig {
        storage_capacity_kb: 100,
        node_id: NodeId::random(),
      };
      let storage = PortalStorage::new(&storage_config).unwrap();

      let key: String = "YlHPPvteGytjbPHbrMOVlK3Z90IcO4UR".to_string();
      let value: String = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".to_string();
      storage.store(&key, &value)

    }

    #[test]
    fn test_get() {

    }

    #[test]
    fn test_get_total_storage() {

      let storage_config = PortalStorageConfig {
        storage_capacity_kb: 100,
        node_id: NodeId::random(),
      };
      let storage = PortalStorage::new(&storage_config).unwrap();

      let kb = storage.get_total_storage_usage_kb();

      println!("{}", kb);

    }

    #[test]
    fn test_distance_to_key() {
        
    }


}

