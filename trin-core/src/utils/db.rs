use std::{env, fs};

use directories::ProjectDirs;
use discv5::enr::NodeId;
use rocksdb::{Options, DB};

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
    application_string.push_str("/rocksdb");

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
