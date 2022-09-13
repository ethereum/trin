use std::path::PathBuf;
use std::{env, fs};
use tracing::debug;

use directories::ProjectDirs;
use discv5::enr::NodeId;
use tempfile::TempDir;

const TRIN_DATA_ENV_VAR: &str = "TRIN_DATA_PATH";

/// Creates a directory on the file system that is deleted once it goes out of scope
pub fn setup_temp_dir() -> TempDir {
    let mut os_temp = env::temp_dir();
    os_temp.push("trin");
    debug!("Creating temp dir: {os_temp:?}");
    fs::create_dir_all(&os_temp).unwrap();

    let temp_dir = TempDir::new_in(&os_temp).unwrap();
    env::set_var(TRIN_DATA_ENV_VAR, temp_dir.path());
    temp_dir
}

pub fn get_data_dir(node_id: NodeId) -> PathBuf {
    let mut trin_data_dir = get_root_path();

    // Append first 8 characters of Node ID
    let mut application_string = "trin_".to_owned();
    let node_id_string = hex::encode(node_id.raw());
    let suffix = &node_id_string[..8];
    application_string.push_str(suffix);

    trin_data_dir.push(application_string);

    fs::create_dir_all(&trin_data_dir).expect("Unable to create data directory folder");
    trin_data_dir
}

/// Get root data path
pub fn get_root_path() -> PathBuf {
    let trin_data_dir = env::var(TRIN_DATA_ENV_VAR).unwrap_or_else(|_| get_default_data_dir());
    PathBuf::from(&trin_data_dir)
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
