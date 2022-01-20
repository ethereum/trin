use std::sync::Arc;
use std::{env, fs};

use directories::ProjectDirs;
use discv5::enr::NodeId;
use rocksdb::{Options, DB};
use sha3::{Digest, Sha3_256};

use crate::portalnet::storage::{DistanceFunction, PortalStorage, PortalStorageConfig};
use crate::portalnet::types::uint::U256;

const TRIN_DATA_ENV_VAR: &str = "TRIN_DATA_PATH";

pub fn get_data_dir(node_id: NodeId) -> String {
    let path = env::var(TRIN_DATA_ENV_VAR).unwrap_or_else(|_| get_default_data_dir(node_id));

    fs::create_dir_all(&path).expect("Unable to create data directory folder");
    path
}

pub fn get_default_data_dir(node_id: NodeId) -> String {
    // Windows: C:\Users\Username\AppData\Roaming\Trin\data
    // macOS: ~/Library/Application Support/Trin
    // Unix-like: $HOME/.local/share/trin

    // Append first 8 characters of Node ID
    let mut application_string = "Trin_".to_owned();
    let node_id_string = hex::encode(node_id.raw());
    let suffix = &node_id_string[..8];
    application_string.push_str(suffix);

    match ProjectDirs::from("", "", &application_string) {
        Some(proj_dirs) => proj_dirs.data_local_dir().to_str().unwrap().to_string(),
        None => panic!("Unable to find data directory"),
    }
}

pub fn setup_overlay_db(node_id: NodeId) -> DB {
    let data_path = get_data_dir(node_id);
    let mut db_opts = Options::default();
    db_opts.create_if_missing(true);
    DB::open(&db_opts, data_path).unwrap()
}

pub fn setup_portal_storage(node_id: NodeId, kb: u32) -> PortalStorage {
    let rocks_db = PortalStorage::setup_rocksdb(node_id).unwrap();
    let meta_db = PortalStorage::setup_sqlite(node_id).unwrap();

    let storage_config = PortalStorageConfig {
        storage_capacity_kb: (kb / 4) as u64,
        node_id,
        distance_function: DistanceFunction::Xor,
        db: Arc::new(rocks_db),
        meta_db: Arc::new(meta_db),
    };
    let storage = PortalStorage::new(storage_config, |key| sha256(key)).unwrap();
    storage
}

// Placeholder content key -> content id conversion function
fn sha256(key: &Vec<u8>) -> U256 {
    let mut hasher = Sha3_256::new();
    hasher.update(key);
    let mut x = hasher.finalize();
    let y: &mut [u8; 32] = x
        .as_mut_slice()
        .try_into()
        .expect("try_into failed in hash placeholder");
    U256::from(*y)
}
