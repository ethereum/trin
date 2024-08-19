use discv5::enr::NodeId;
use ethportal_api::types::cli::HISTORY_NETWORK;
use tempfile::TempDir;

use crate::{error::ContentStoreError, PortalStorageConfig, PortalStorageConfigFactory};

/// Creates temporary directory and PortalStorageConfig.
pub fn create_test_portal_storage_config_with_capacity(
    capacity_mb: u64,
) -> Result<(TempDir, PortalStorageConfig), ContentStoreError> {
    let temp_dir = TempDir::new()?;
    let config = PortalStorageConfigFactory::new(
        capacity_mb,
        &[HISTORY_NETWORK.to_string()],
        NodeId::random(),
        temp_dir.path().to_path_buf(),
    )
    .unwrap()
    .create(HISTORY_NETWORK);
    Ok((temp_dir, config))
}

pub fn generate_random_bytes(length: usize) -> Vec<u8> {
    (0..length).map(|_| rand::random::<u8>()).collect()
}
