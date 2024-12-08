use std::{
    env, fs,
    path::{Path, PathBuf},
};

use alloy::primitives::B256;
use anyhow::{anyhow, bail};
use discv5::enr::{CombinedKey, Enr, NodeId};
use ethportal_api::{
    types::network::Network,
    utils::bytes::{hex_decode, hex_encode},
};
use trin_utils::dir::setup_data_dir;

const APP_NAME: &str = "trin";
const TRIN_DATA_ENV_VAR: &str = "TRIN_DATA_PATH";
const UNSAFE_PRIVATE_KEY_FILE_NAME: &str = "unsafe_private_key.hex";

pub fn configure_trin_data_dir(
    data_dir: Option<PathBuf>,
    ephemeral: bool,
) -> anyhow::Result<PathBuf> {
    let env_path = env::var(TRIN_DATA_ENV_VAR).ok().map(PathBuf::from);
    if data_dir.is_some() && env_path.is_some() {
        bail!("Both --data_dir flag and {TRIN_DATA_ENV_VAR} env var are set.");
    }
    Ok(setup_data_dir(APP_NAME, data_dir.or(env_path), ephemeral)?)
}

/// Configures active node data dir based on the provided private key.
/// Returns the private key used to configure the node data dir.
/// If no private key is provided, the application private key is used.
pub fn configure_node_data_dir(
    trin_data_dir: &Path,
    private_key: Option<B256>,
    network: Network,
) -> anyhow::Result<(PathBuf, B256)> {
    let pk = match private_key {
        // user has provided a custom private key...
        Some(val) => CombinedKey::secp256k1_from_bytes(val.0.clone().as_mut_slice())
            .map_err(|e| anyhow!("When building server key pair: {e:?}"))?,
        None => get_application_private_key(trin_data_dir)?,
    };
    let node_id = Enr::empty(&pk)?.node_id();
    let node_data_dir = get_node_data_dir(trin_data_dir, node_id, network);
    fs::create_dir_all(&node_data_dir)?;
    Ok((node_data_dir, B256::from_slice(&pk.encode())))
}

/// Returns the node data directory associated with the provided node id.
fn get_node_data_dir(trin_data_dir: &Path, node_id: NodeId, network: Network) -> PathBuf {
    // Append first 8 characters of Node ID
    let mut application_string = "".to_owned();
    if network != Network::Mainnet {
        application_string.push_str(&network.to_string());
        application_string.push('_');
    }
    application_string.push_str("trin_");
    let node_id_string = hex::encode(node_id.raw());
    let suffix = &node_id_string[..8];
    application_string.push_str(suffix);
    trin_data_dir.join(application_string)
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
    use serial_test::serial;
    use trin_utils::dir::create_temp_test_dir;

    use super::*;

    #[test]
    #[serial]
    fn app_private_key() {
        let temp_dir = create_temp_test_dir().unwrap();
        let (_, active_pk) =
            configure_node_data_dir(temp_dir.path(), None, Network::Angelfood).unwrap();
        let app_pk = get_application_private_key(temp_dir.path()).unwrap();
        let app_pk = B256::from_slice(&app_pk.encode());
        assert_eq!(active_pk, app_pk);
        temp_dir.close().unwrap();
    }

    #[test]
    #[serial]
    fn custom_private_key() {
        let temp_dir = create_temp_test_dir().unwrap();
        let pk = CombinedKey::generate_secp256k1();
        let pk = B256::from_slice(&pk.encode());
        let (_, active_pk) =
            configure_node_data_dir(temp_dir.path(), Some(pk), Network::Angelfood).unwrap();
        assert_eq!(pk, active_pk);
        temp_dir.close().unwrap();
    }

    #[test]
    #[serial]
    fn activated_private_key_persists_over_reconfigurations() {
        let temp_dir = create_temp_test_dir().unwrap();
        let (_, app_pk) =
            configure_node_data_dir(temp_dir.path(), None, Network::Angelfood).unwrap();

        // configure data dir to use a custom pk
        let pk = CombinedKey::generate_secp256k1();
        let pk = B256::from_slice(&pk.encode());
        let _ = configure_node_data_dir(temp_dir.path(), Some(pk), Network::Angelfood).unwrap();

        // reconfigure data dir with no pk, should use the original app pk
        let (_, app_pk_2) =
            configure_node_data_dir(temp_dir.path(), None, Network::Angelfood).unwrap();
        assert_eq!(app_pk, app_pk_2);
        temp_dir.close().unwrap();
    }
}
