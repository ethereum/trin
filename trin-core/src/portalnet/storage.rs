use rocksdb::{Options, DB, Error};
use crate::utils::{get_data_dir, xor_two_values};
use discv5::enr::NodeId;
use rusqlite::{params, Connection, Result};
use std::fs;
use log::{error};
use hex;
use std::convert::TryInto;

#[derive(Copy, Clone)]
pub enum DistanceFunction {
    Xor,
    State,
}

type ContentKeyToIdDerivationFunction = dyn Fn(&String) -> [u8; 32];

pub struct PortalStorageConfig  {

    pub storage_capacity_kb: u64,
    pub node_id: NodeId,
    pub distance_function: DistanceFunction,
    
}

pub struct PortalStorage {

    node_id: NodeId,
    storage_capacity_kb: u64,
    data_radius: u64,
    farthest_content_id: Option<[u8; 32]>,
    db: rocksdb::DB,
    meta_db: rusqlite::Connection,
    distance_function: DistanceFunction,
    content_key_to_id_function: Box<ContentKeyToIdDerivationFunction>,

}

impl PortalStorage {

    pub fn new(config: &PortalStorageConfig, convert_function: impl Fn(&String) -> [u8; 32] + 'static) -> Result<Self, String> {

        // Create DB interfaces
        let db = PortalStorage::setup_rocksdb();
        let meta_db = PortalStorage::setup_sqlite();

        // Initialize the instance
        let mut storage = Self {
            node_id: config.node_id,
            storage_capacity_kb: config.storage_capacity_kb,
            data_radius: u64::MAX,
            db: db,
            farthest_content_id: None,
            meta_db: meta_db,
            distance_function: config.distance_function,
            content_key_to_id_function: Box::new(convert_function)
        };

        // Check whether we already have data, and if so 
        // use it to set the farthest_key and data_radius fields
        match storage.find_farthest_content_id() {
            Some(content_id) => {
                storage.farthest_content_id = Some(content_id.clone());
                if storage.capacity_reached() {
                    storage.data_radius = storage.distance_to_content_id(&content_id);
                }
            }
            // No farthest key found, carry on with blank slate settings
            None => ()
        }

        Ok(storage)

    }

    fn setup_rocksdb() -> DB {

        let data_path_root: String = get_data_dir().to_owned();
        let data_suffix: &str = "/rocksdb";
        let data_path = data_path_root + data_suffix;

        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        DB::open(&db_opts, data_path).unwrap()

    }

    fn setup_sqlite() -> rusqlite::Connection {

        let data_path_root: String = get_data_dir().to_owned();
        let data_suffix: &str = "/trin.sqlite";
        let data_path = data_path_root + data_suffix;

        let conn = Connection::open(data_path).unwrap();

        conn.execute(
            CREATE_QUERY,
            [],
        ).unwrap();

        conn

    }

    // Calls the content_key_to_id callback closure that was passed in.
    pub fn content_key_to_content_id(&self, key: &String) -> [u8; 32] {

        (self.content_key_to_id_function)(key)

    }
    
    
    pub fn should_store(&self, key: &String) -> bool {

        let content_id = self.content_key_to_content_id(key);

        // Don't store if we already have the data
        match self.db.get(&content_id) {
            Ok(Some(_)) => {
                return false;
            },
            Err(e) => panic!("Unable to respond to FindContent: {}", e),
            _ => ()
        }

        // Don't store if it's outside our radius
        if self.data_radius < u64::MAX {
            self.distance_to_content_id(&content_id) < self.data_radius
        } else {
            true
        }

    }

    fn meta_db_insert(&self, content_id: &[u8; 32], content_key: &String, value: &String) {

        let content_id_as_u32: u32 = PortalStorage::byte_vector_to_u32(content_id.clone().to_vec());

        let value_size = value.len();

        self.meta_db.execute(
            INSERT_QUERY,
            params![content_id.to_vec(), content_id_as_u32, content_key, value_size],
        ).unwrap();

    }

    fn meta_db_remove(&self, content_id: &[u8; 32]) {

        self.meta_db.execute(
            DELETE_QUERY,
            [content_id.to_vec()],
        ).unwrap();
        
    }

    pub fn store(&mut self, key: &String, value: &String) {

        // Check whether we should store this data
        if !self.should_store(&key) {
            println!("Not storing: {}", key);
            return;
        }   

        let content_id = self.content_key_to_content_id(key);

        // Store the data 
        self.db.put(&content_id, value).expect("Failed to write to DB");
        self.meta_db_insert(&content_id, &key, value);

        // Update the farthest key if this key is either 1.) the first key ever or 2.) farther than the current farthest
        match self.farthest_content_id.as_ref() {
            None => {
                self.farthest_content_id = Some(content_id);
            },
            Some(farthest) => {
                if self.distance_to_content_id(&content_id) > self.distance_to_content_id(&farthest) {
                    self.farthest_content_id = Some(content_id.clone());
                }
            }
        }

        // Delete furthest data until our data usage is less than capacity
        while self.capacity_reached() {

            let id_to_remove = self.farthest_content_id.clone();
            
            println!("Capacity reached, deleting farthest: {}", hex::encode(&id_to_remove.clone().unwrap()));

            self.db.delete(&id_to_remove.clone().unwrap()).expect("Failed to delete key.");
            self.meta_db_remove(&id_to_remove.clone().unwrap());

            self.db.flush().expect("Failed to flush db.");
            
            match self.find_farthest_content_id() {
                None => { error!("Failed to find farthest!") },
                Some(farthest) => {
                    println!("Found new farthest: {}", hex::encode(&farthest));
                    self.farthest_content_id = Some(farthest.clone());
                    self.data_radius = self.distance_to_content_id(&farthest);
                }
            }

        } 

    }

    pub fn get(&self, key: &String) -> Result<Option<Vec<u8>>, Error> {

        let content_id = self.content_key_to_content_id(key);
        self.db.get(content_id)

    }

    pub fn get_current_radius(&self) -> u64 {

        self.data_radius

    }

    pub fn capacity_reached(&self) -> bool {

        let storage_usage = self.get_total_storage_usage_in_bytes_from_network().unwrap();
        storage_usage > (self.storage_capacity_kb * 1000)

    }

    pub fn get_total_storage_usage_in_bytes_on_disk(&self) -> u64 {

        self.get_total_size_of_directory_in_bytes(get_data_dir()).unwrap()

    }

    pub fn get_total_storage_usage_in_bytes_from_network(&self) -> Result<u64, String> {

        let mut query = self.meta_db.prepare(
            TOTAL_DATA_SIZE_QUERY,
        ).unwrap();

        let result = query.query_map([], |row| {
            Ok(DataSizeSum {
                sum: row.get(0)?,
            })
        });

        let x = result.unwrap().next().unwrap().unwrap().sum;

        Ok(x)

    }

    // Returns None if there's no data in the DB yet
    pub fn find_farthest_content_id(&self) -> Option<[u8; 32]> {

        let result = match self.distance_function {

            DistanceFunction::Xor => {

                let node_id_u32 = PortalStorage::byte_vector_to_u32(self.node_id.raw().to_vec());

                let mut query = self.meta_db.prepare(
                    XOR_FIND_FARTHEST_QUERY,
                ).unwrap();

                let results = query.query_map([node_id_u32], |row| {
                    Ok(ContentId {
                        id_long: row.get(0)?,
                    })
                });

                let mut result = results.expect("Error reading from SQLite.");

                let result = match result.next() {
                    Some(row) => {
                        row
                    }
                    None => { return None; }
                };
                let result = result.expect("Error getting row data from SQLite.").id_long;
                let result_vec: [u8; 32] = match result.try_into() {
                    Ok(vec) => vec,
                    Err(e) => panic!("Expected 32 bytes from vector but got {}", e.len())
                };
                result_vec
            }

            DistanceFunction::State => {
                panic!("State distance function is not implemented yet.")
            }

        };

        Some(result)

    }

    fn get_total_size_of_directory_in_bytes(&self, path: String) -> std::io::Result<u64> {

        let metadata = match fs::metadata(&path) {
            Ok(metadata) => { metadata }
            Err(_) => { return Ok(0); }
        };
        let mut size = metadata.len();

        if metadata.is_dir() {
            for entry in fs::read_dir(&path)? {
                let dir = entry?;
                let path_string = dir.path().into_os_string().into_string();
                size += self.get_total_size_of_directory_in_bytes(path_string.unwrap())?;
            }
        }
        
        Ok(size)

    }

    pub fn distance_to_content_id(&self, content_id: &[u8; 32]) -> u64 {

        let byte_vector = xor_two_values(
            content_id, &self.node_id.raw().to_vec()
        );

        PortalStorage::byte_vector_to_u64(byte_vector)
        
    }

    // Takes the most significant 8 bytes of a vector and casts them into a u64.
    // The equivalent of a conversion from nanometers to meters.
    pub fn byte_vector_to_u64(vec: Vec<u8>) -> u64 {

        if vec.len() < 8 {
            println!("Error: XOR returned less than 8 bytes.");
            return 0;
        }

        let mut array: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
        for (index, byte) in vec.iter().take(8).enumerate() {
            array[index] = byte.clone();
        }
      
        u64::from_be_bytes(array)

    }

    pub fn byte_vector_to_u32(vec: Vec<u8>) -> u32 {

        if vec.len() < 4 {
            println!("Error: XOR returned less than 4 bytes.");
            return 0;
        }

        let mut array: [u8; 4] = [0, 0, 0, 0];
        for (index, byte) in vec.iter().take(4).enumerate() {
            array[index] = byte.clone();
        }
      
        u32::from_be_bytes(array)

    }

}

const CREATE_QUERY: &str = "create table if not exists content_metadata (
                                content_id_long TEXT PRIMARY KEY,
                                content_id_short INTEGER NOT NULL,
                                content_key TEXT NOT NULL,
                                content_size INTEGER
                            )";

const INSERT_QUERY: &str = "INSERT INTO content_metadata (content_id_long, content_id_short, content_key, content_size)
                            VALUES (?1, ?2, ?3, ?4)";

const DELETE_QUERY: &str = "DELETE FROM content_metadata
                            WHERE content_id_long = (?1)";

const XOR_FIND_FARTHEST_QUERY: &str = "SELECT
                                    content_id_long
                                    FROM content_metadata
                                    ORDER BY ((?1 | content_id_short) - (?1 & content_id_short)) DESC";

const TOTAL_DATA_SIZE_QUERY: &str = "SELECT SUM(content_size) FROM content_metadata";

struct ContentId {
    id_long: Vec<u8>,
}

struct DataSizeSum {
    sum: u64,
}

#[cfg(test)]
mod test {

    use sha3::{Digest, Sha3_256};
    use std::convert::TryInto;

    use super::*;

    // Placeholder content key -> content id conversion function
    fn sha256(key: &String) -> [u8; 32] {

        let mut hasher = Sha3_256::new();
        hasher.update(key);
        let mut x = hasher.finalize();
        let y: &mut[u8; 32] = x.as_mut_slice().try_into().expect("Wrong length");
        y.clone()
    
    }      

    #[test]
    fn test_new() {

        let storage_config = PortalStorageConfig {
            storage_capacity_kb: 100,
            node_id: NodeId::random(),
            distance_function: DistanceFunction::Xor,
        };
        let _ = PortalStorage::new(&storage_config, |key| {
            sha256(&key)
        });

    }

    #[test]
    fn test_store() {

        let storage_config = PortalStorageConfig {
            storage_capacity_kb: 100,
            node_id: NodeId::random(),
            distance_function: DistanceFunction::Xor,
        };

        let mut storage = PortalStorage::new(&storage_config, |key| {
            sha256(&key)
        }).unwrap();

        let key: String = "YlHPPvteGytjbPHbrMOVlK3Z90IcO4UR".to_string();
        let value: String = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".to_string();
        storage.store(&key, &value);

    }

    #[test]
    fn test_get_data() {

        let storage_config = PortalStorageConfig {
            storage_capacity_kb: 100,
            node_id: NodeId::random(),
            distance_function: DistanceFunction::Xor,
        };
        let mut storage = PortalStorage::new(&storage_config, |key| {
            sha256(&key)
        }).unwrap();
        let key: String = "YlHPPvteGytjbPHbrMOVlK3Z90IcO4UR".to_string();
        let value: String = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".to_string();
        storage.store(&key, &value);

        let result = storage.get(&key);

        println!("{}", String::from_utf8(result.unwrap().unwrap()).unwrap());

    }

    #[test]
    fn test_get_total_storage() {

        let storage_config = PortalStorageConfig {
            storage_capacity_kb: 100,
            node_id: NodeId::random(),
            distance_function: DistanceFunction::Xor,
        };
        let mut storage = PortalStorage::new(&storage_config, |key| {
            sha256(&key)
        }).unwrap();

        let key: String = "YlHPPvteGytjbPHbrMOVlK3Z90IcO4UR".to_string();
        let value: String = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".to_string();
        storage.store(&key, &value);

        let bytes = storage.get_total_storage_usage_in_bytes_from_network();

        println!("{}", bytes.unwrap());

    }


    #[test]
    fn test_should_store() {

        let storage_config = PortalStorageConfig {
            storage_capacity_kb: 100,
            node_id: NodeId::random(),
            distance_function: DistanceFunction::Xor,
        };

        let mut storage = PortalStorage::new(&storage_config, |key| {
            sha256(&key)
        }).unwrap();

        let key_a: String = "YlHPPvteGytjbPHbrMOVlK3Z90IcO4UR".to_string();
        let key_b: String = "p1K8ymqgNO9vJ1LwATa4yNqCxk6AMgNa".to_string();
        let value: String = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".to_string();

        storage.store(&key_a, &value);

        let should_store_a = storage.should_store(&key_a);
        let should_store_b = storage.should_store(&key_b);

        assert_eq!(should_store_a, false);
        assert_eq!(should_store_b, true);

    }


    #[test]
    fn test_distance_to_key() {
        
        // As u64: 5543900367377300341
        let example_node_id_bytes: [u8; 32] = [76, 239, 228, 2, 227, 174, 123, 117, 195, 237, 200, 80, 219, 0, 188, 225, 18, 196, 162, 89, 204, 144, 204, 187, 71, 12, 147, 65, 19, 65, 167, 110];

        let storage_config = PortalStorageConfig {
            storage_capacity_kb: 100,
            node_id: NodeId::parse(&example_node_id_bytes).unwrap(),
            distance_function: DistanceFunction::Xor,
        };

        let storage = PortalStorage::new(&storage_config, |key| {
            sha256(&key)
        }).unwrap();

        // As u64: 3352017618602726004
        let key: String = "YlHPPvteGytjbPHbrMOVlK3Z90IcO4UR".to_string();
        let content_id = storage.content_key_to_content_id(&key);

        let distance = storage.distance_to_content_id(&content_id);

        // Answer from https://xor.pw/
        assert_eq!(distance, 7091804100148652289);

    }

    fn distance_to_content_key(storage: &PortalStorage, key: &String) -> u64 {

        let content_id = storage.content_key_to_content_id(key);
        storage.distance_to_content_id(&content_id)

    }

    #[test]
    // This test will only pass if the database isn't already populated,
    // otherwise we can't guarantee it will get the expected answer
    fn test_find_farthest() {

        // As u64: 5543900367377300341
        let example_node_id_bytes: [u8; 32] = [76, 239, 228, 2, 227, 174, 123, 117, 195, 237, 200, 80, 219, 0, 188, 225, 18, 196, 162, 89, 204, 144, 204, 187, 71, 12, 147, 65, 19, 65, 167, 110];

        let storage_config = PortalStorageConfig {
            storage_capacity_kb: 100,
            node_id: NodeId::parse(&example_node_id_bytes).unwrap(),
            distance_function: DistanceFunction::Xor,
        };

        let mut storage = PortalStorage::new(&storage_config, |key| {
            sha256(&key)
        }).unwrap();

        let value = "value".to_string();

        let key_a: String = "YlHPPvteGytjbPHbrMOVlK3Z90IcO4UR".to_string();
        println!("A: {}", PortalStorage::byte_vector_to_u64(storage.content_key_to_content_id(&key_a).to_vec()));
        storage.store(&key_a, &value);
        println!("A Distance: {}", distance_to_content_key(&storage, &key_a));

        // This one is the farthest
        let key_b: String = "LHp1PeJ4C6c3nRUc7f6BI1FYULNL8aWB".to_string();
        println!("B: {}", PortalStorage::byte_vector_to_u64(storage.content_key_to_content_id(&key_b).to_vec()));
        storage.store(&key_b, &value);
        println!("B Distance: {}", distance_to_content_key(&storage, &key_b));
        let b_content_id = storage.content_key_to_content_id(&key_b);

        let key_c: String = "HkybBgUebGtbwdrNDbxDWywtgWlUM8vW".to_string();
        println!("C: {}", PortalStorage::byte_vector_to_u64(storage.content_key_to_content_id(&key_c).to_vec()));
        storage.store(&key_c, &value);
        println!("C Distance: {}", distance_to_content_key(&storage, &key_c));

        let key_d: String = "gdOKkDEq9XFs2Tzay4Ecuw0obIISGw9Y".to_string();
        println!("D: {}", PortalStorage::byte_vector_to_u64(storage.content_key_to_content_id(&key_d).to_vec()));
        storage.store(&key_d, &value);
        println!("D Distance: {}", distance_to_content_key(&storage, &key_d));
        
        let result = storage.find_farthest_content_id().unwrap();

        assert_eq!(result, b_content_id);

    }

}
