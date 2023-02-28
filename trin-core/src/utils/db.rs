use std::path::PathBuf;
use std::{env, fs};

use anyhow::anyhow;
use directories::ProjectDirs;
use discv5::enr::NodeId;
use tempfile::TempDir;
use tracing::debug;

const TRIN_DATA_ENV_VAR: &str = "TRIN_DATA_PATH";

/// Creates a directory on the file system that is deleted once it goes out of scope
pub fn setup_temp_dir() -> anyhow::Result<TempDir> {
    let mut os_temp = env::temp_dir();
    os_temp.push("trin");
    debug!("Creating temp dir: {os_temp:?}");
    fs::create_dir_all(&os_temp)?;

    let temp_dir = TempDir::new_in(&os_temp)?;
    env::set_var(TRIN_DATA_ENV_VAR, temp_dir.path());
    Ok(temp_dir)
}

pub fn get_data_dir(node_id: NodeId) -> anyhow::Result<PathBuf> {
    let mut trin_data_dir = get_root_path()?;

    // Append first 8 characters of Node ID
    let mut application_string = "trin_".to_owned();
    let node_id_string = hex::encode(node_id.raw());
    let suffix = &node_id_string[..8];
    application_string.push_str(suffix);

    trin_data_dir.push(application_string);

    fs::create_dir_all(&trin_data_dir).expect("Unable to create data directory folder");
    Ok(trin_data_dir)
}

/// Get root data path
pub fn get_root_path() -> anyhow::Result<PathBuf> {
    let trin_data_dir = match env::var(TRIN_DATA_ENV_VAR) {
        Ok(val) => val,
        Err(_) => get_default_data_dir()?,
    };
    Ok(PathBuf::from(&trin_data_dir))
}

pub fn get_default_data_dir() -> anyhow::Result<String> {
    // Windows: C:\Users\Username\AppData\Roaming\trin
    // macOS: ~/Library/Application Support/trin
    // Unix-like: $HOME/.local/share/trin
    match ProjectDirs::from("", "", "trin") {
        Some(proj_dirs) => match proj_dirs.data_local_dir().to_str() {
            Some(val) => Ok(val.to_string()),
            None => Err(anyhow!("Unable to find default data directory")),
        },
        None => Err(anyhow!("Unable to find default data directory")),
    }
}
