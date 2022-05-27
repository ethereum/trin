use std::{env, fs, path::Path};

use directories::ProjectDirs;
use discv5::enr::NodeId;

const TRIN_DATA_ENV_VAR: &str = "TRIN_DATA_PATH";

pub fn get_data_dir(node_id: NodeId) -> String {
    let trin_data_dir = env::var(TRIN_DATA_ENV_VAR).unwrap_or_else(|_| get_default_data_dir());
    let trin_data_dir = Path::new(&trin_data_dir);

    // Append first 8 characters of Node ID
    let mut application_string = "trin_".to_owned();
    let node_id_string = hex::encode(node_id.raw());
    let suffix = &node_id_string[..8];
    application_string.push_str(suffix);

    let node_id_data_dir = trin_data_dir
        .join(application_string)
        .to_str()
        .unwrap()
        .to_string();
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
