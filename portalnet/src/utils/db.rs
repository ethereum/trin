use std::{
    env, fs,
    path::{Path, PathBuf},
};

use alloy_primitives::B256;
use anyhow::anyhow;
use directories::ProjectDirs;
use discv5::enr::{CombinedKey, Enr, NodeId};
use tempfile::TempDir;
use tracing::debug;

use ethportal_api::{
    types::cli::DEFAULT_NETWORK,
    utils::bytes::{hex_decode, hex_encode},
};

const TRIN_DATA_ENV_VAR: &str = "TRIN_DATA_PATH";
const TRIN_DATA_DIR: &str = "trin";
const UNSAFE_PRIVATE_KEY_FILE_NAME: &str = "unsafe_private_key.hex";

/// Create a directory on the file system that is deleted once it goes out of scope
pub fn setup_temp_dir() -> anyhow::Result<TempDir> {
    let mut os_temp = env::temp_dir();
    os_temp.push(TRIN_DATA_DIR);
    debug!("Creating temp dir: {os_temp:?}");
    fs::create_dir_all(&os_temp)?;

    let temp_dir = TempDir::new_in(&os_temp)?;
    env::set_var(TRIN_DATA_ENV_VAR, temp_dir.path());

    Ok(temp_dir)
}

pub fn configure_trin_data_dir(ephemeral: bool) -> anyhow::Result<PathBuf> {
    if ephemeral {
        setup_temp_dir().map(|temp_dir| temp_dir.into_path())
    } else {
        // Return the active trin data directory, either default or user specified.
        let trin_data_dir = match env::var(TRIN_DATA_ENV_VAR) {
            Ok(val) => PathBuf::from(val),
            Err(_) => get_default_data_dir()?,
        };
        fs::create_dir_all(&trin_data_dir)?;
        Ok(trin_data_dir)
    }
}

/// Configures active node data dir based on the provided private key.
/// Returns the private key used to configure the node data dir.
/// If no private key is provided, the application private key is used.
pub fn configure_node_data_dir(
    trin_data_dir: PathBuf,
    private_key: Option<B256>,
    network_name: String,
) -> anyhow::Result<(PathBuf, B256)> {
    let pk = match private_key {
        // user has provided a custom private key...
        Some(val) => CombinedKey::secp256k1_from_bytes(val.0.clone().as_mut_slice())
            .map_err(|e| anyhow!("When building server key pair: {e:?}"))?,
        None => get_application_private_key(&trin_data_dir)?,
    };
    let node_id = Enr::empty(&pk)?.node_id();
    let node_data_dir = get_node_data_dir(trin_data_dir, node_id, network_name);
    fs::create_dir_all(&node_data_dir)?;
    Ok((node_data_dir, B256::from_slice(&pk.encode())))
}

/// Returns the node data directory associated with the provided node id.
fn get_node_data_dir(trin_data_dir: PathBuf, node_id: NodeId, network_name: String) -> PathBuf {
    // Append first 8 characters of Node ID
    let mut application_string = "".to_owned();
    if network_name != DEFAULT_NETWORK {
        application_string.push_str(&network_name);
        application_string.push('_');
    }
    application_string.push_str("trin_");
    let node_id_string = hex::encode(node_id.raw());
    let suffix = &node_id_string[..8];
    application_string.push_str(suffix);
    trin_data_dir.join(application_string)
}

fn get_default_data_dir() -> anyhow::Result<PathBuf> {
    // Windows: C:\Users\Username\AppData\Roaming\trin
    // macOS: ~/Library/Application Support/trin
    // Unix-like: $HOME/.local/share/trin
    match ProjectDirs::from("", "", TRIN_DATA_DIR) {
        Some(proj_dirs) => match proj_dirs.data_local_dir().to_str() {
            Some(val) => Ok(PathBuf::from(val)),
            None => Err(anyhow!("Unable to find default data directory")),
        },
        None => Err(anyhow!("Unable to find default data directory")),
    }
}

/// Returns application private key.
/// If the private key does not exist (eg. brand new trin data dir),
/// a random pk is generated and stored.
fn get_application_private_key(trin_data_dir: &Path) -> anyhow::Result<CombinedKey> {
    let unsafe_private_key_file = trin_data_dir.join(UNSAFE_PRIVATE_KEY_FILE_NAME);
    if !unsafe_private_key_file.exists() {
        let pk = CombinedKey::generate_secp256k1();
        let pk_hex = hex_encode(pk.encode());
        fs::write(&unsafe_private_key_file, pk_hex)?;
    }
    let private_key = fs::read_to_string(unsafe_private_key_file)?;
    let mut private_key = hex_decode(&private_key)?;
    Ok(CombinedKey::secp256k1_from_bytes(&mut private_key)?)
}

#[cfg(test)]
pub mod test {
    use super::*;

    use serial_test::serial;

    #[test]
    #[serial]
    fn app_private_key() {
        let temp_dir = setup_temp_dir().unwrap();
        let (_, active_pk) =
            configure_node_data_dir(temp_dir.path().to_path_buf(), None, "test".to_string())
                .unwrap();
        let app_pk = get_application_private_key(temp_dir.path()).unwrap();
        let app_pk = B256::from_slice(&app_pk.encode());
        temp_dir.close().unwrap();
        assert_eq!(active_pk, app_pk);
    }

    #[test]
    #[serial]
    fn custom_private_key() {
        let temp_dir = setup_temp_dir().unwrap();
        let pk = CombinedKey::generate_secp256k1();
        let pk = B256::from_slice(&pk.encode());
        let (_, active_pk) =
            configure_node_data_dir(temp_dir.path().to_path_buf(), Some(pk), "test".to_string())
                .unwrap();
        temp_dir.close().unwrap();
        assert_eq!(pk, active_pk);
    }

    #[test]
    #[serial]
    fn activated_private_key_persists_over_reconfigurations() {
        let temp_dir = setup_temp_dir().unwrap();
        let (_, app_pk) =
            configure_node_data_dir(temp_dir.path().to_path_buf(), None, "test".to_string())
                .unwrap();

        // configure data dir to use a custom pk
        let pk = CombinedKey::generate_secp256k1();
        let pk = B256::from_slice(&pk.encode());
        let _ =
            configure_node_data_dir(temp_dir.path().to_path_buf(), Some(pk), "test".to_string())
                .unwrap();

        // reconfigure data dir with no pk, should use the original app pk
        let (_, app_pk_2) =
            configure_node_data_dir(temp_dir.path().to_path_buf(), None, "test".to_string())
                .unwrap();
        temp_dir.close().unwrap();
        assert_eq!(app_pk, app_pk_2);
    }
}
