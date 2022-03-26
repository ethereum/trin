use std::path::Path;
use std::{env, fs};

use crate::cli::TrinConfig;
use directories::ProjectDirs;
use discv5::enr::NodeId;
use log::debug;
use std::sync::Mutex;

lazy_static! {
    static ref TRIN_NODE_ID_DATA_DIRS: Mutex<Vec<String>> = Mutex::new(vec![]);
}
const TRIN_DATA_ENV_VAR: &str = "TRIN_DATA_PATH";

pub fn get_data_dir(node_id: NodeId) -> String {
    let trin_data_dir = env::var(TRIN_DATA_ENV_VAR).unwrap_or_else(|_| get_default_data_dir());
    let trin_data_dir = Path::new(&trin_data_dir);

    // Append first 8 characters of Node ID
    let mut application_string = "Trin_".to_owned();
    let node_id_string = hex::encode(node_id.raw());
    let suffix = &node_id_string[..8];
    application_string.push_str(suffix);

    let node_id_data_dir = trin_data_dir
        .join(application_string)
        .to_str()
        .unwrap()
        .to_string();
    TRIN_NODE_ID_DATA_DIRS
        .lock()
        .unwrap()
        .push(node_id_data_dir.to_owned());
    fs::create_dir_all(&node_id_data_dir).expect("Unable to create data directory folder");
    node_id_data_dir
}

pub fn get_default_data_dir() -> String {
    // Windows: C:\Users\Username\AppData\Roaming\trin
    // macOS: ~/Library/Application Support/trin
    // Unix-like: $HOME/.local/share/trin
    match ProjectDirs::from("", "", "trin") {
        Some(proj_dirs) => proj_dirs.data_local_dir().to_str().unwrap().to_string(),
        None => panic!("Unable to find data directory"),
    }
}

pub fn cleanup_data_dir() {
    // TODO: Once TrieDB and PortalStorage are merged, and Trin uses a single
    // data directory, we should update TRIN_NODE_IDE_DATA_DIRS to a string.
    let trin_config = TrinConfig::from_cli();
    if trin_config.ephemeral {
        let paths = TRIN_NODE_ID_DATA_DIRS.lock().unwrap();
        for path in &*paths {
            if let Err(err) = fs::remove_dir_all(path) {
                debug!("Ctrl-C: Skipped removing {} because: {}", path, err);
            };
        }
    }
}
