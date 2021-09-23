use crate::portalnet::U256;
use directories::ProjectDirs;
use discv5::enr::NodeId;
use rocksdb::{Options, DB};
use std::{env, fs};

const TRIN_DATA_ENV_VAR: &str = "TRIN_DATA_PATH";

pub fn xor_two_values(first: &[u8], second: &[u8]) -> Vec<u8> {
    if first.len() != second.len() {
        panic!("Can only xor vectors of equal length.")
    };

    first
        .iter()
        .zip(&mut second.iter())
        .map(|(&first, &second)| first ^ second)
        .collect()
}

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
    let node_id_string = U256::from(node_id.raw()).to_string();
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_xor_two_zeros() {
        let one = vec![0];
        let two = vec![0];
        assert_eq!(xor_two_values(&one, &two), [0]);
    }

    #[test]
    fn test_xor_two_values() {
        let one = vec![1, 0, 0];
        let two = vec![0, 0, 1];
        assert_eq!(xor_two_values(&one, &two), [1, 0, 1]);
    }

    #[test]
    #[should_panic(expected = "Can only xor vectors of equal length.")]
    fn test_xor_panics_with_different_lengths() {
        let one = vec![1, 0];
        let two = vec![0, 0, 1];
        xor_two_values(&one, &two);
    }

}
