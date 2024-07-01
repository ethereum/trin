use std::{env, fs, path::PathBuf};

use anyhow::anyhow;
use directories::ProjectDirs;
use rocksdb::{Options, DB as RocksDB};
use tempfile::TempDir;
use tracing::{debug, info};

const TRIN_EXECUTION_DATA_DIR: &str = "trin-execution";

/// Helper function for opening a RocksDB connection for the radius-constrained db.
pub fn setup_rocksdb(path: PathBuf) -> anyhow::Result<RocksDB> {
    let rocksdb_path = path.join("rocksdb");
    info!(path = %rocksdb_path.display(), "Setting up RocksDB");

    let mut db_opts = Options::default();
    db_opts.create_if_missing(true);

    // Set the max number of open files to 150. MacOs has a default limit of 256 open files per
    // process. This limit prevents issues with the OS running out of file descriptors.
    db_opts.set_max_open_files(150);
    Ok(RocksDB::open(&db_opts, rocksdb_path)?)
}

/// Create a directory on the file system that is deleted once it goes out of scope
pub fn setup_temp_dir() -> anyhow::Result<TempDir> {
    let mut os_temp = env::temp_dir();
    os_temp.push(TRIN_EXECUTION_DATA_DIR);
    debug!("Creating temp dir: {os_temp:?}");
    fs::create_dir_all(&os_temp)?;

    let temp_dir = TempDir::new_in(&os_temp)?;

    Ok(temp_dir)
}

pub fn get_default_data_dir() -> anyhow::Result<PathBuf> {
    // Windows: C:\Users\Username\AppData\Roaming\$TRIN_EXECUTION_DATA_DIR
    // macOS: ~/Library/Application Support/$TRIN_EXECUTION_DATA_DIR
    // Unix-like: $HOME/.local/share/$TRIN_EXECUTION_DATA_DIR
    match ProjectDirs::from("", "", TRIN_EXECUTION_DATA_DIR) {
        Some(proj_dirs) => match proj_dirs.data_local_dir().to_str() {
            Some(val) => Ok(PathBuf::from(val)),
            None => Err(anyhow!("Unable to find default data directory")),
        },
        None => Err(anyhow!("Unable to find default data directory")),
    }
}
