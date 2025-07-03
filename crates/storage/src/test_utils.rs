use discv5::enr::NodeId;
use ethportal_api::types::{distance::Distance, network::Subnetwork};
use tempfile::TempDir;

use crate::{
    config::StorageCapacityConfig, error::ContentStoreError, PortalStorageConfig,
    PortalStorageConfigFactory,
};

/// Creates temporary directory and PortalStorageConfig.
pub fn create_test_portal_storage_config_with_capacity(
    capacity_mb: u32,
) -> Result<(TempDir, PortalStorageConfig), ContentStoreError> {
    let temp_dir = TempDir::new()?;
    let config = PortalStorageConfigFactory::new(
        StorageCapacityConfig::Combined {
            total_mb: capacity_mb,
            subnetworks: vec![Subnetwork::LegacyHistory],
        },
        NodeId::random(),
        temp_dir.path().to_path_buf(),
    )
    .unwrap()
    .create(&Subnetwork::LegacyHistory, Distance::MAX)
    .unwrap();
    Ok((temp_dir, config))
}

pub fn generate_random_bytes(length: usize) -> Vec<u8> {
    (0..length).map(|_| rand::random::<u8>()).collect()
}
