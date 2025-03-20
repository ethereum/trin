use std::path::PathBuf;

use ethportal_api::types::network::Subnetwork;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use crate::{versioned::ContentType, PortalStorageConfig};

/// The config for the EphemeralV1Store
#[derive(Clone, Debug)]
pub struct EphemeralV1StoreConfig {
    pub content_type: ContentType,
    pub subnetwork: Subnetwork,
    pub node_data_dir: PathBuf,
    pub sql_connection_pool: Pool<SqliteConnectionManager>,
}

#[allow(unused)]
impl EphemeralV1StoreConfig {
    pub fn new(
        content_type: ContentType,
        subnetwork: Subnetwork,
        config: PortalStorageConfig,
    ) -> Self {
        Self {
            content_type,
            subnetwork,
            node_data_dir: config.node_data_dir,
            sql_connection_pool: config.sql_connection_pool,
        }
    }
}
