use super::U256;
use crate::utils::{db::get_data_dir, xor_two_values};
use discv5::enr::NodeId;
use hex;
use log;
use log::debug;
use log::error;
use rocksdb::{Options, DB};
use rusqlite::{params, Connection};
use std::convert::TryInto;
use std::fs;
use std::sync::Arc;
use thiserror::Error;

#[derive(Copy, Clone)]
pub enum DistanceFunction {
    Xor,
    State,
}

/// Signature of the function that must be passed into the call to new.
type ContentKeyToIdDerivationFunction = dyn Fn(&String) -> U256;

/// Struct for configuring a PortalStorage instance.
pub struct PortalStorageConfig {
    pub storage_capacity_kb: u64,
    pub node_id: NodeId,
    pub distance_function: DistanceFunction,
    pub db: Arc<rocksdb::DB>,
    pub meta_db: Arc<rusqlite::Connection>,
}

/// Struct whose public methods abstract away Kademlia-based storage behavior.
pub struct PortalStorage {
    node_id: NodeId,
    storage_capacity_in_bytes: u64,
    data_radius: u64,
    farthest_content_id: Option<[u8; 32]>,
    db: Arc<rocksdb::DB>,
    meta_db: Arc<rusqlite::Connection>,
    distance_function: DistanceFunction,
    content_key_to_id_function: Box<ContentKeyToIdDerivationFunction>,
}

/// Error type returned in a Result by any failable public PortalStorage methods.
#[derive(Debug, Error)]
pub enum PortalStorageError {
    #[error("RocksDB Error")]
    RocksDB(#[from] rocksdb::Error),

    #[error("Sqlite Error")]
    Sqlite(#[from] rusqlite::Error),

    #[error("IO Error")]
    IOError(#[from] std::io::Error),

    #[error("Sum data size error: received None from SQLite")]
    SumError(),

    #[error("While {doing:?}, expected to receive data of size {expected:?} but found data of size {actual:?}")]
    DataSizeError {
        doing: String,
        expected: usize,
        actual: usize,
    },

    #[error("String error value returned from {function_name:?}: {error:?}")]
    StringError {
        function_name: String,
        error: std::ffi::OsString,
    },
}

impl PortalStorage {
    /// Public constructor for building a PortalStorage object.
    /// Checks whether a populated database already exists vs a fresh instance.
    pub fn new(
        config: PortalStorageConfig,
        content_key_to_id_function: impl Fn(&String) -> U256 + 'static,
    ) -> Result<Self, PortalStorageError> {
        // Initialize the instance
        let mut storage = Self {
            node_id: config.node_id,
            storage_capacity_in_bytes: config.storage_capacity_kb * 1000,
            data_radius: u64::MAX,
            db: config.db,
            farthest_content_id: None,
            meta_db: config.meta_db,
            distance_function: config.distance_function,
            content_key_to_id_function: Box::new(content_key_to_id_function),
        };

        // Check whether we already have data, and if so
        // use it to set the farthest_key and data_radius fields
        match storage.find_farthest_content_id()? {
            Some(content_id) => {
                storage.farthest_content_id = Some(content_id.clone());
                if storage.capacity_reached()? {
                    storage.data_radius = storage.distance_to_content_id(&content_id);
                }
            }
            // No farthest key found, carry on with blank slate settings
            None => (),
        }

        Ok(storage)
    }

    /// Public method for determining whether a given content key should be stored by the node.
    /// Takes into account our data radius and whether we are already storing the data.
    pub fn should_store(&self, key: &String) -> Result<bool, PortalStorageError> {
        let content_id = self.content_key_to_content_id(key);

        // Don't store if we already have the data
        match self.db.get(&content_id) {
            Ok(Some(_)) => return Ok(false),
            Err(e) => return Err(PortalStorageError::RocksDB(e)),
            _ => (),
        }

        // Don't store if it's outside our radius
        if self.data_radius < u64::MAX {
            Ok(self.distance_to_content_id(&content_id) < self.data_radius)
        } else {
            Ok(true)
        }
    }

    /// Public method for storing a given value for a given content-key.
    pub fn store(&mut self, key: &String, value: &String) -> Result<(), PortalStorageError> {
        let content_id = self.content_key_to_content_id(key);

        let distance_to_content_id = self.distance_to_content_id(&content_id);

        // Check whether data is outside our radius.
        if distance_to_content_id > self.data_radius {
            debug!("Not storing: {}", key);
            return Ok(());
        }

        // Store the data.
        self.db_insert(&content_id, value)?;
        self.meta_db_insert(&content_id, &key, value)?;

        // Update the farthest key if this key is either 1.) the first key ever or 2.) farther than the current farthest.
        match self.farthest_content_id.as_ref() {
            None => {
                self.farthest_content_id = Some(content_id);
            }
            Some(farthest) => {
                // if self.distance_to_content_id(&content_id) > self.distance_to_content_id(&farthest)
                if distance_to_content_id > self.distance_to_content_id(&farthest) {
                    self.farthest_content_id = Some(content_id.clone());
                }
            }
        }

        // Delete furthest data until our data usage is less than capacity.
        while self.capacity_reached()? {
            // Unwrap because this was set in the block before this loop.
            let id_to_remove = self.farthest_content_id.clone().unwrap();

            debug!(
                "Capacity reached, deleting farthest: {}",
                hex::encode(&id_to_remove)
            );

            self.db.delete(&id_to_remove)?;
            self.meta_db_remove(&id_to_remove)?;

            match self.find_farthest_content_id()? {
                None => {
                    error!("Database is over-capacity, but could not find find entry to delete!");
                    self.farthest_content_id = None;
                    // stop attempting to delete to avoid infinite loop
                    break;
                }
                Some(farthest) => {
                    debug!("Found new farthest: {}", hex::encode(&farthest));
                    self.farthest_content_id = Some(farthest.clone());
                    self.data_radius = self.distance_to_content_id(&farthest);
                }
            }
        }

        Ok(())
    }

    /// Public method for retrieving the stored value for a given content-key.
    /// If no value exists for the given content-key, Result<None> is returned.
    pub fn get(&self, key: &String) -> Result<Option<Vec<u8>>, PortalStorageError> {
        let content_id = self.content_key_to_content_id(key);
        Ok(self.db.get(content_id)?)
    }

    /// Public method for retrieving the node's current radius.
    pub fn get_current_radius(&self) -> U256 {
        let u64_radius_bytes: [u8; 8] = u64::to_be_bytes(self.data_radius);
        let empty_bytes: [u8; 24] = [0; 24];
        let combined_array: [u8; 32] = {
            let mut whole: [u8; 32] = [255; 32];
            let (one, two) = whole.split_at_mut(u64_radius_bytes.len());
            one.copy_from_slice(&u64_radius_bytes);
            two.copy_from_slice(&empty_bytes);
            whole
        };
        U256::from(combined_array)
    }

    /// Public method for determining how much actual disk space is being used to store this node's Portal Network data.
    /// Intended for analysis purposes. PortalStorage's capacity decision-making is not based off of this method.
    pub fn get_total_storage_usage_in_bytes_on_disk(&self) -> Result<u64, PortalStorageError> {
        Ok(self.get_total_size_of_directory_in_bytes(get_data_dir(self.node_id))?)
    }

    /// Calls the content_key_to_id callback closure that was passed into the constructor.
    fn content_key_to_content_id(&self, key: &String) -> [u8; 32] {
        let id_as_u256: U256 = (self.content_key_to_id_function)(key);

        let mut content_id: [u8; 32] = [0; 32];
        id_as_u256.to_big_endian(&mut content_id);

        content_id.clone()
    }

    /// Internal method for inserting data into the db.
    fn db_insert(&self, content_id: &[u8; 32], value: &String) -> Result<(), PortalStorageError> {
        self.db.put(&content_id, value)?;
        Ok(())
    }

    /// Internal method for inserting data into the meta db.
    fn meta_db_insert(
        &self,
        content_id: &[u8; 32],
        content_key: &String,
        value: &String,
    ) -> Result<(), PortalStorageError> {
        let content_id_as_u32: u32 = PortalStorage::byte_vector_to_u32(content_id.clone().to_vec());

        let value_size = value.len();

        match self.meta_db.execute(
            INSERT_QUERY,
            params![
                content_id.to_vec(),
                content_id_as_u32,
                content_key,
                value_size
            ],
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(PortalStorageError::Sqlite(e)),
        }
    }

    /// Internal method for removing a given content-id from the meta db.
    fn meta_db_remove(&self, content_id: &[u8; 32]) -> Result<(), PortalStorageError> {
        self.meta_db.execute(DELETE_QUERY, [content_id.to_vec()])?;
        Ok(())
    }

    /// Internal method for determining whether the node is over-capacity.
    fn capacity_reached(&self) -> Result<bool, PortalStorageError> {
        let storage_usage = self.get_total_storage_usage_in_bytes_from_network()?;
        Ok(storage_usage > self.storage_capacity_in_bytes)
    }

    /// Internal method for measuring the total amount of requestable data that the node is storing.
    fn get_total_storage_usage_in_bytes_from_network(&self) -> Result<u64, PortalStorageError> {
        let mut query = self.meta_db.prepare(TOTAL_DATA_SIZE_QUERY)?;

        let result = query.query_map([], |row| Ok(DataSizeSum { sum: row.get(0)? }));

        let sum = match result?.next() {
            Some(x) => x,
            None => {
                return Err(PortalStorageError::SumError());
            }
        }?
        .sum;

        Ok(sum)
    }

    /// Internal method for finding the piece of stored data that has the farthest content id from our
    /// node id, according to xor distance. Used to determine which data to drop when at a capacity.
    fn find_farthest_content_id(&self) -> Result<Option<[u8; 32]>, PortalStorageError> {
        let result = match self.distance_function {
            DistanceFunction::Xor => {
                let node_id_u32 = PortalStorage::byte_vector_to_u32(self.node_id.raw().to_vec());

                let mut query = self.meta_db.prepare(XOR_FIND_FARTHEST_QUERY)?;

                let mut result = query.query_map([node_id_u32], |row| {
                    Ok(ContentId {
                        id_long: row.get(0)?,
                    })
                })?;

                let result = match result.next() {
                    Some(row) => row,
                    None => {
                        return Ok(None);
                    }
                };
                let result = result?.id_long;
                let result_vec: [u8; 32] = match result.len() {
                    // If exact data size, safe to expect conversion.
                    32 => result.try_into().expect(
                        "Unexpectedly failed to convert 32 element vec to 32 element array.",
                    ),
                    // Received data of size other than 32 bytes.
                    x => {
                        return Err(PortalStorageError::DataSizeError {
                            doing: "finding farthest content id".to_string(),
                            expected: 32,
                            actual: x,
                        });
                    }
                };
                result_vec
            }

            DistanceFunction::State => {
                panic!("State distance function is not implemented yet.")
            }
        };

        Ok(Some(result))
    }

    /// Internal method used to measure on-disk storage usage.
    fn get_total_size_of_directory_in_bytes(
        &self,
        path: String,
    ) -> Result<u64, PortalStorageError> {
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => {
                return Ok(0);
            }
        };
        let mut size = metadata.len();

        if metadata.is_dir() {
            for entry in fs::read_dir(&path)? {
                let dir = entry?;
                let path_string = match dir.path().into_os_string().into_string() {
                    Ok(string) => string,
                    Err(error_string) => {
                        return Err(PortalStorageError::StringError {
                            function_name: "get_total_size_of_directory_in_bytes".to_string(),
                            error: error_string,
                        });
                    }
                };
                size += self.get_total_size_of_directory_in_bytes(path_string)?;
            }
        }

        Ok(size)
    }

    /// Internal method that returns the distance between our node ID and a given content ID
    fn distance_to_content_id(&self, content_id: &[u8; 32]) -> u64 {
        let byte_vector = xor_two_values(content_id, &self.node_id.raw().to_vec());

        PortalStorage::byte_vector_to_u64(byte_vector)
    }

    // Takes the most significant 8 bytes of a vector and casts them into a u64.
    // With a 32-byte big-endian unsigned integer input, this is equivalent to dividing by 2^(256 - 32)
    fn byte_vector_to_u64(vec: Vec<u8>) -> u64 {
        if vec.len() < 8 {
            debug!("Error: XOR returned less than 8 bytes.");
            return 0;
        }

        let mut array: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
        for (index, byte) in vec.iter().take(8).enumerate() {
            array[index] = byte.clone();
        }

        u64::from_be_bytes(array)
    }

    // Converts most significant 4 bytes of a vector to a u32.
    fn byte_vector_to_u32(vec: Vec<u8>) -> u32 {
        if vec.len() < 4 {
            debug!("Error: XOR returned less than 4 bytes.");
            return 0;
        }

        let mut array: [u8; 4] = [0, 0, 0, 0];
        for (index, byte) in vec.iter().take(4).enumerate() {
            array[index] = byte.clone();
        }

        u32::from_be_bytes(array)
    }

    /// Helper function for opening a SQLite connection.
    /// Used for testing.
    pub fn setup_rocksdb(node_id: NodeId) -> Result<rocksdb::DB, PortalStorageError> {
        let data_path_root: String = get_data_dir(node_id).to_owned();
        let data_suffix: &str = "/rocksdb";
        let data_path = data_path_root + data_suffix;

        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        Ok(DB::open(&db_opts, data_path)?)
    }

    /// Helper function for opening a SQLite connection.
    /// Used for testing.
    pub fn setup_sqlite(node_id: NodeId) -> Result<rusqlite::Connection, PortalStorageError> {
        let data_path_root: String = get_data_dir(node_id).to_owned();
        let data_suffix: &str = "/trin.sqlite";
        let data_path = data_path_root + data_suffix;

        let conn = Connection::open(data_path)?;

        conn.execute(CREATE_QUERY, [])?;

        Ok(conn)
    }
}

// SQLite Statements
const CREATE_QUERY: &str = "create table if not exists content_metadata (
                                content_id_long TEXT PRIMARY KEY,
                                content_id_short INTEGER NOT NULL,
                                content_key TEXT NOT NULL,
                                content_size INTEGER
                            )";

const INSERT_QUERY: &str =
    "INSERT OR IGNORE INTO content_metadata (content_id_long, content_id_short, content_key, content_size)
                            VALUES (?1, ?2, ?3, ?4)";

const DELETE_QUERY: &str = "DELETE FROM content_metadata
                            WHERE content_id_long = (?1)";

const XOR_FIND_FARTHEST_QUERY: &str = "SELECT
                                    content_id_long
                                    FROM content_metadata
                                    ORDER BY ((?1 | content_id_short) - (?1 & content_id_short)) DESC";

const TOTAL_DATA_SIZE_QUERY: &str = "SELECT SUM(content_size) FROM content_metadata";

// SQLite Result Containers
struct ContentId {
    id_long: Vec<u8>,
}

struct DataSizeSum {
    sum: u64,
}

#[cfg(test)]
pub mod test {

    use super::*;
    use sha3::{Digest, Sha3_256};
    use std::convert::TryInto;

    // Placeholder content key -> content id conversion function
    fn sha256(key: &str) -> U256 {
        let mut hasher = Sha3_256::new();
        hasher.update(key);
        let mut x = hasher.finalize();
        let y: &mut [u8; 32] = x
            .as_mut_slice()
            .try_into()
            .expect("try_into failed in hash placeholder");
        U256::from(y.clone())
    }

    #[test]
    fn test_new() -> Result<(), PortalStorageError> {
        let node_id = NodeId::random();

        let db = Arc::new(PortalStorage::setup_rocksdb(node_id)?);
        let meta_db = Arc::new(PortalStorage::setup_sqlite(node_id)?);

        const CAPACITY: u64 = 100;

        let storage_config = PortalStorageConfig {
            storage_capacity_kb: CAPACITY,
            node_id,
            distance_function: DistanceFunction::Xor,
            db: db,
            meta_db: meta_db,
        };
        let storage = PortalStorage::new(storage_config, |key| sha256(key))?;

        // Assert that configs match the storage object's fields
        assert_eq!(storage.node_id, node_id);
        assert_eq!(storage.storage_capacity_in_bytes, CAPACITY * 1000);

        Ok(())
    }

    #[test]
    fn test_store() -> Result<(), PortalStorageError> {
        let node_id = NodeId::random();

        let db = Arc::new(PortalStorage::setup_rocksdb(node_id)?);
        let meta_db = Arc::new(PortalStorage::setup_sqlite(node_id)?);

        let storage_config = PortalStorageConfig {
            storage_capacity_kb: 100,
            node_id,
            distance_function: DistanceFunction::Xor,
            db: db,
            meta_db: meta_db,
        };

        let mut storage = PortalStorage::new(storage_config, |key| sha256(key))?;

        let key: String = "YlHPPvteGytjbPHbrMOVlK3Z90IcO4UR".to_string();
        let value: String = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".to_string();
        storage.store(&key, &value)?;

        Ok(())
    }

    #[test]
    fn test_get_data() -> Result<(), PortalStorageError> {
        let node_id = NodeId::random();

        let db = Arc::new(PortalStorage::setup_rocksdb(node_id)?);
        let meta_db = Arc::new(PortalStorage::setup_sqlite(node_id)?);

        let storage_config = PortalStorageConfig {
            storage_capacity_kb: 100,
            node_id,
            distance_function: DistanceFunction::Xor,
            db: db,
            meta_db: meta_db,
        };
        let mut storage = PortalStorage::new(storage_config, |key| sha256(key))?;
        let key: String = "YlHPPvteGytjbPHbrMOVlK3Z90IcO4UR".to_string();
        let value: String = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".to_string();
        storage.store(&key, &value)?;

        let result = storage.get(&key);

        let string = String::from_utf8(result.unwrap().unwrap()).unwrap();

        assert_eq!(string, value);

        Ok(())
    }

    #[test]
    fn test_get_total_storage() -> Result<(), PortalStorageError> {
        let node_id = NodeId::random();

        let db = Arc::new(PortalStorage::setup_rocksdb(node_id)?);
        let meta_db = Arc::new(PortalStorage::setup_sqlite(node_id)?);

        let storage_config = PortalStorageConfig {
            storage_capacity_kb: 100,
            node_id,
            distance_function: DistanceFunction::Xor,
            db: db,
            meta_db: meta_db,
        };
        let mut storage = PortalStorage::new(storage_config, |key| sha256(key))?;

        let key: String = "YlHPPvteGytjbPHbrMOVlK3Z90IcO4UR".to_string();
        let value: String = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".to_string();
        storage.store(&key, &value)?;

        let bytes = storage.get_total_storage_usage_in_bytes_from_network()?;

        assert_eq!(32, bytes);

        Ok(())
    }

    #[test]
    fn test_should_store() -> Result<(), PortalStorageError> {
        let node_id = NodeId::random();

        let db = Arc::new(PortalStorage::setup_rocksdb(node_id)?);
        let meta_db = Arc::new(PortalStorage::setup_sqlite(node_id)?);

        let storage_config = PortalStorageConfig {
            storage_capacity_kb: 100,
            node_id,
            distance_function: DistanceFunction::Xor,
            db: db,
            meta_db: meta_db,
        };

        let mut storage = PortalStorage::new(storage_config, |key| sha256(key))?;

        let key_a: String = "YlHPPvteGytjbPHbrMOVlK3Z90IcO4UR".to_string();
        let key_b: String = "p1K8ymqgNO9vJ1LwATa4yNqCxk6AMgNa".to_string();
        let value: String = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".to_string();

        storage.store(&key_a, &value)?;

        let should_store_a = storage.should_store(&key_a)?;
        let should_store_b = storage.should_store(&key_b)?;

        assert_eq!(should_store_a, false);
        assert_eq!(should_store_b, true);

        Ok(())
    }

    #[test]
    fn test_distance_to_key() -> Result<(), PortalStorageError> {
        // As u64: 5615957961415228277
        let example_node_id_bytes: [u8; 32] = [
            77, 239, 228, 2, 227, 174, 123, 117, 195, 237, 200, 80, 219, 0, 188, 225, 18, 196, 162,
            89, 204, 144, 204, 187, 71, 12, 147, 65, 19, 65, 167, 110,
        ];
        let node_id = match NodeId::parse(&example_node_id_bytes) {
            Ok(node_id) => node_id,
            Err(string) => panic!("Failed to parse Node ID: {}", string),
        };

        let db = Arc::new(PortalStorage::setup_rocksdb(node_id)?);
        let meta_db = Arc::new(PortalStorage::setup_sqlite(node_id)?);

        let storage_config = PortalStorageConfig {
            storage_capacity_kb: 100,
            node_id,
            distance_function: DistanceFunction::Xor,
            db: db,
            meta_db: meta_db,
        };

        let storage = PortalStorage::new(storage_config, |key| sha256(key))?;

        // As u64: 3352017618602726004
        let key: String = "YlHPPvteGytjbPHbrMOVlK3Z90IcO4UR".to_string();
        let content_id = storage.content_key_to_content_id(&key);

        let distance = storage.distance_to_content_id(&content_id);

        // Answer from https://xor.pw/
        assert_eq!(distance, 7163861694186580225);

        Ok(())
    }

    #[test]
    fn test_find_farthest() -> Result<(), PortalStorageError> {
        // As u64: 5543900367377300341
        let example_node_id_bytes: [u8; 32] = [
            76, 239, 228, 2, 227, 174, 123, 117, 195, 237, 200, 80, 219, 0, 188, 225, 18, 196, 162,
            89, 204, 144, 204, 187, 71, 12, 147, 65, 19, 65, 167, 110,
        ];
        let node_id = match NodeId::parse(&example_node_id_bytes) {
            Ok(node_id) => node_id,
            Err(string) => panic!("Failed to parse Node ID: {}", string),
        };

        let db = Arc::new(PortalStorage::setup_rocksdb(node_id)?);
        let meta_db = Arc::new(PortalStorage::setup_sqlite(node_id)?);

        let storage_config = PortalStorageConfig {
            storage_capacity_kb: 100,
            node_id,
            distance_function: DistanceFunction::Xor,
            db: db,
            meta_db: meta_db,
        };

        let mut storage = PortalStorage::new(storage_config, |key| sha256(key))?;

        let value = "value".to_string();

        let key_a: String = "YlHPPvteGytjbPHbrMOVlK3Z90IcO4UR".to_string();
        storage.store(&key_a, &value)?;

        // This one is the farthest
        let key_b: String = "LHp1PeJ4C6c3nRUc7f6BI1FYULNL8aWB".to_string();
        storage.store(&key_b, &value)?;
        let expected_content_id = storage.content_key_to_content_id(&key_b);

        let key_c: String = "HkybBgUebGtbwdrNDbxDWywtgWlUM8vW".to_string();
        storage.store(&key_c, &value)?;

        let key_d: String = "gdOKkDEq9XFs2Tzay4Ecuw0obIISGw9Y".to_string();
        storage.store(&key_d, &value)?;

        let result = storage.find_farthest_content_id().unwrap().unwrap();

        assert_eq!(result, expected_content_id);

        Ok(())
    }
}
