use rocksdb::{Options, DB, Error, perf};
use crate::utils::{get_data_dir, xor_two_values};
use discv5::enr::NodeId;
use rusqlite::{params, Connection, Result};
use std::fs;
use log::{error};

pub struct PortalStorageConfig {

    pub storage_capacity_kb: u64,
    pub node_id: NodeId,
    
}

pub struct PortalStorage {

    node_id: NodeId,
    storage_capacity_kb: u64,
    data_radius: u64,
    farthest_key: Option<String>,
    db: rocksdb::DB,
    meta_db: rusqlite::Connection,
    capacity_reached: bool

}

impl PortalStorage {

    pub fn new(config: &PortalStorageConfig) -> Result<Self, String> {

        // Create DB interfaces
        let db = PortalStorage::setup_rocksdb();
        let meta_db = PortalStorage::setup_sqlite();

        // Initialize the instance
        let storage = Self {
            node_id: config.node_id,
            storage_capacity_kb: config.storage_capacity_kb,
            data_radius: u64::MAX,
            db: db,
            farthest_key: None,
            meta_db: meta_db,
            capacity_reached: false
        };

        Ok(storage)

    }

    fn setup_rocksdb() -> DB {

        let data_path_root: String = get_data_dir().to_owned();
        let data_suffix: &str = "/rocksdb";
        let data_path = data_path_root + data_suffix;

        println!("ROCKSDB DATAPATH: {}", data_path);

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
    
    pub fn should_store(&self, key: &String) -> bool {

        // println!("Data radius:     {}", self.data_radius);
        // println!("Max u64:         {}", u64::MAX);
        // println!("Distance to key: {}", self.distance_to_key(key));

        // Don't store if we already have the data, otherwise continue.
        match self.db.get(&key) {
            Ok(Some(_)) => {
                return false;
            },
            Err(e) => panic!("Unable to respond to FindContent: {}", e),
            _ => ()
        }

        if self.data_radius < u64::MAX {
            self.distance_to_key(key) < self.data_radius
        } else {
            true
        }

    }

    // 1.) Don't store data outside the radius.
    // 2.) Store the data, and then if we're at capacity, drop the farthest and find the new farthest.
    // 3.) Initialize or update farthest_key if necessary.
    // 4.) Check whether we've gone over capacity.
    pub fn store(&mut self, key: &String, value: &String) {

        if !self.should_store(key) {
            println!("Not storing.");
            return;
        }

        self.db.put(key, value).expect("Failed to write to DB");

        let key_as_u32: u32 = PortalStorage::byte_vector_to_u32(key.clone().into_bytes());
        println!("Key inserting into SQL: {}", key_as_u32);

        self.meta_db.execute(
            INSERT_QUERY,
            params![key, key_as_u32],
        ).unwrap();

        if self.capacity_reached {

            println!("Capacity was reached previously.");

            let key_to_remove = &self.farthest_key;
            self.db.delete(key_to_remove.as_ref().unwrap()).expect("Failed to delete key.");
            let key_to_remove_as_u32 = PortalStorage::byte_vector_to_u32(key_to_remove.clone().unwrap().into_bytes());
            self.meta_db.execute(
                DELETE_QUERY,
                [key_to_remove_as_u32],
            ).unwrap();
            
            match self.find_farthest() {
                Err(e) => {
                    error!("Failed to find farthest: {}", e);
                },
                Ok(farthest) => {
                    self.farthest_key = Some(farthest.clone());
                    self.data_radius = self.distance_to_key(&farthest);
                }
            }

        } else {

            let data_usage = self.get_total_storage_usage_kb();
            println!("Data usage: {}", data_usage);
            println!("Capacity:   {}", self.storage_capacity_kb);
            if data_usage > self.storage_capacity_kb {
                println!("Capacity has been reached!");
                self.capacity_reached = true;
            }

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

    pub fn get_current_radius(&self) -> u64 {

        self.data_radius

    }

    pub fn get_total_storage_usage_kb(&self) -> u64 {

        let p: perf::MemoryUsageStats = perf::get_memory_usage_stats(Some(&[&self.db]), None)
                                            .expect("Failed to get memory usage statistics.");

        let db_total = self.get_total_size_of_directory_in_bytes(get_data_dir()).unwrap();

        let total_in_bytes = p.mem_table_total + db_total;

        ( total_in_bytes / 1000 ) as u64

    }

    pub fn find_farthest(&self) -> Result<String, String> {

        let node_id_u32 = PortalStorage::byte_vector_to_u32(self.node_id.raw().to_vec());

        let mut query = self.meta_db.prepare(
            FIND_FARTHEST_QUERY,
        ).unwrap();

        println!("BEFORE THE CRASH THE NODE IS {}", node_id_u32);   
        let results = query.query_map([node_id_u32], |row| {
            Ok(ContentKey {
                key_long: row.get(0)?,
            })
        });

        let x = results.unwrap().next().unwrap().unwrap().key_long;

        Ok(x)

    }

    fn get_total_size_of_directory_in_bytes(&self, path: String) -> std::io::Result<u64> {

        let metadata = fs::metadata(&path).unwrap();
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

    pub fn distance_to_key(&self, key: &String) -> u64 {

        let byte_vector = xor_two_values(
            key.as_bytes(), &self.node_id.raw().to_vec()
        );

        PortalStorage::byte_vector_to_u64(byte_vector)
        
    }

    // Takes the most significant 8 bytes of a vector and casts them into a u64.
    // Useful in this class when the full bytes represent a u256, and for most purposes we only
    // need to compare the most significant 8 bytes of the u256 to compare 
    // relative distances. The equivalent of a conversion from nanometers to meters.
    fn byte_vector_to_u64(vec: Vec<u8>) -> u64 {

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

    fn byte_vector_to_u32(vec: Vec<u8>) -> u32 {

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

const CREATE_QUERY: &str = "create table if not exists content_keys (
                                id INTEGER PRIMARY KEY,
                                content_key_full TEXT NOT NULL,
                                content_key_short INTEGER NOT NULL
                            )";

const INSERT_QUERY: &str = "INSERT INTO content_keys (content_key_full, content_key_short)
                            VALUES (?1, ?2)";

const DELETE_QUERY: &str = "DELETE FROM content_keys
                            WHERE content_key_full = (?1)";

const FIND_FARTHEST_QUERY: &str = "SELECT
                                    content_key_full
                                    FROM content_keys
                                    ORDER BY ((?1 | content_key_short) - (?1 & content_key_short)) DESC";

struct ContentKey {
    key_long: String,
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


        let mut storage = PortalStorage::new(&storage_config).unwrap();

        let key: String = "YlHPPvteGytjbPHbrMOVlK3Z90IcO4UR".to_string();
        let value: String = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".to_string();
        storage.store(&key, &value);

    }

    #[test]
    fn test_get_data() {

        let storage_config = PortalStorageConfig {
            storage_capacity_kb: 100,
            node_id: NodeId::random(),
        };
        let mut storage = PortalStorage::new(&storage_config).unwrap();
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
        };
        let mut storage = PortalStorage::new(&storage_config).unwrap();

        let key: String = "YlHPPvteGytjbPHbrMOVlK3Z90IcO4UR".to_string();
        let value: String = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".to_string();
        storage.store(&key, &value);

        let kb = storage.get_total_storage_usage_kb();

        println!("{}", kb);

    }


    #[test]
    fn test_should_store() {

        let storage_config = PortalStorageConfig {
            storage_capacity_kb: 100,
            node_id: NodeId::random(),
        };

        let mut storage = PortalStorage::new(&storage_config).unwrap();

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
        };

        let storage = PortalStorage::new(&storage_config).unwrap();

        // As u64: 6443604676644861029
        let key: String = "YlHPPvteGytjbPHbrMOVlK3Z90IcO4UR".to_string();
        let distance = storage.distance_to_key(&key);

        // Answer from https://xor.pw/
        assert_eq!(distance, 1550272167950159632);

    }

    #[test]
    fn test_find_farthest() {

        // As u64: 5543900367377300341
        let example_node_id_bytes: [u8; 32] = [76, 239, 228, 2, 227, 174, 123, 117, 195, 237, 200, 80, 219, 0, 188, 225, 18, 196, 162, 89, 204, 144, 204, 187, 71, 12, 147, 65, 19, 65, 167, 110];

        let storage_config = PortalStorageConfig {
            storage_capacity_kb: 100,
            node_id: NodeId::parse(&example_node_id_bytes).unwrap(),
        };

        let mut storage = PortalStorage::new(&storage_config).unwrap();

        let value = "value".to_string();

        // As u64: 6443604676644861029
        // Distance from our Node ID: 1550272167950159632
        let key_a: String = "YlHPPvteGytjbPHbrMOVlK3Z90IcO4UR".to_string();
        println!("A: {}", PortalStorage::byte_vector_to_u64(key_a.as_bytes().to_vec()));
        storage.store(&key_a, &value);
        println!("A Distance: {}", storage.distance_to_key(&key_a));

        // As u64: 5496766702310214196
        // Distance from our Node ID: 47169270891360577
        let key_b: String = "LHp1PeJ4C6c3nRUc7f6BI1FYULNL8aWB".to_string();
        println!("B: {}", PortalStorage::byte_vector_to_u64(key_b.as_bytes().to_vec()));
        storage.store(&key_b, &value);
        println!("B Distance: {}", storage.distance_to_key(&key_b));

        // As u64: 5218398056166675813
        // Distance from our Node ID: 325558111434255888
        let key_c: String = "HkybBgUebGtbwdrNDbxDWywtgWlUM8vW".to_string();
        println!("C: {}", PortalStorage::byte_vector_to_u64(key_c.as_bytes().to_vec()));
        storage.store(&key_c, &value);
        println!("C Distance: {}", storage.distance_to_key(&key_c));

        // This one is the farthest.
        // As u64: 7450166868918420849
        // Distance from our Node ID: 3137789897711697412
        let key_d: String = "gdOKkDEq9XFs2Tzay4Ecuw0obIISGw9Y".to_string();
        println!("D: {}", PortalStorage::byte_vector_to_u64(key_d.as_bytes().to_vec()));
        storage.store(&key_d, &value);
        println!("D Distance: {}", storage.distance_to_key(&key_d));
        
        let result = storage.find_farthest().unwrap();

        assert_eq!(result, key_d);

    }

}
