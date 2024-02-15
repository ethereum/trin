use ethportal_api::types::portal_wire::ProtocolId;
use r2d2::PooledConnection;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{named_params, OptionalExtension};
use trin_metrics::{portalnet::PORTALNET_METRICS, storage::StorageMetricsReporter};

use crate::{error::ContentStoreError, PortalStorageConfig};

use super::{sql, store::VersionedContentStore, ContentType, StoreVersion};

/// Ensures that the correct version of the content store is used (by migrating the content if
/// that's not the case).
pub fn create_store<S: VersionedContentStore>(
    content_type: ContentType,
    network: ProtocolId,
    config: PortalStorageConfig,
) -> Result<S, ContentStoreError> {
    let conn = config.sql_connection_pool.get()?;

    let old_version = lookup_store_version(content_type, &conn)?;

    match old_version {
        Some(old_version) => {
            // Migrate if version doesn't match
            if S::version() != old_version {
                S::migrate_from(content_type, old_version, &config)?;
                update_store_info(content_type, S::version(), &conn)?;
            }
        }
        None => {
            update_store_info(content_type, S::version(), &conn)?;
        }
    }

    S::create(
        content_type,
        config,
        StorageMetricsReporter {
            protocol: network.to_string(),
            storage_metrics: PORTALNET_METRICS.storage(),
        },
    )
}

fn lookup_store_version(
    content_type: ContentType,
    conn: &PooledConnection<SqliteConnectionManager>,
) -> Result<Option<StoreVersion>, ContentStoreError> {
    Ok(conn
        .query_row(
            sql::STORE_INFO_LOOKUP,
            named_params! { ":content_type": content_type.as_ref() },
            |row| {
                let version: StoreVersion = row.get("version")?;
                Ok(version)
            },
        )
        .optional()?)
}

fn update_store_info(
    content_type: ContentType,
    store_version: StoreVersion,
    conn: &PooledConnection<SqliteConnectionManager>,
) -> Result<(), ContentStoreError> {
    conn.execute(
        sql::STORE_INFO_UPDATE,
        named_params! {
            ":content_type": content_type.as_ref(),
            ":version": store_version.as_ref(),
        },
    )?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod test {
    use anyhow::Result;
    use discv5::enr::NodeId;

    use crate::utils::setup_test_sql;

    use super::*;

    fn setup_config() -> PortalStorageConfig {
        let node_id = NodeId::random();
        PortalStorageConfig::new_for_testing(node_id, /* storage_capacity_mb= */ 1).unwrap()
    }

    #[test]
    fn lookup_no_store_version() -> Result<()> {
        let conn = setup_test_sql()?.get()?;

        assert_eq!(lookup_store_version(ContentType::State, &conn)?, None);
        Ok(())
    }

    #[test]
    fn insert_store_verion() -> Result<()> {
        let conn = setup_test_sql()?.get()?;

        update_store_info(ContentType::State, StoreVersion::IdIndexed, &conn)?;

        assert_eq!(
            lookup_store_version(ContentType::State, &conn)?,
            Some(StoreVersion::IdIndexed)
        );
        Ok(())
    }

    #[test]
    fn update_store_verion() -> Result<()> {
        let conn = setup_test_sql()?.get()?;

        // Set store version
        update_store_info(ContentType::State, StoreVersion::LegacyContentData, &conn)?;
        assert_eq!(
            lookup_store_version(ContentType::State, &conn)?,
            Some(StoreVersion::LegacyContentData)
        );

        // Update store version
        update_store_info(ContentType::State, StoreVersion::IdIndexed, &conn)?;
        assert_eq!(
            lookup_store_version(ContentType::State, &conn)?,
            Some(StoreVersion::IdIndexed)
        );

        Ok(())
    }

    #[test]
    fn create_store_no_old_version() -> Result<()> {
        let config = setup_config();

        // Should be successful
        create_store::<DummyContentStore>(ContentType::State, ProtocolId::State, config.clone())?;

        assert_eq!(
            lookup_store_version(ContentType::State, &config.sql_connection_pool.get()?)?,
            Some(StoreVersion::IdIndexed)
        );

        Ok(())
    }

    #[test]
    fn create_store_same_old_version() -> Result<()> {
        let config = setup_config();

        update_store_info(
            ContentType::State,
            StoreVersion::IdIndexed,
            &config.sql_connection_pool.get()?,
        )?;

        // Should be successful
        create_store::<DummyContentStore>(ContentType::State, ProtocolId::State, config.clone())?;

        assert_eq!(
            lookup_store_version(ContentType::State, &config.sql_connection_pool.get()?)?,
            Some(StoreVersion::IdIndexed)
        );

        Ok(())
    }

    #[test]
    #[should_panic = "UnsupportedStoreMigration"]
    fn create_store_different_old_version() {
        let config = setup_config();

        update_store_info(
            ContentType::State,
            StoreVersion::LegacyContentData,
            &config.sql_connection_pool.get().unwrap(),
        )
        .unwrap();

        // Should panic - DummyContentStore doesn't support migration.
        create_store::<DummyContentStore>(ContentType::State, ProtocolId::State, config).unwrap();
    }

    pub struct DummyContentStore;

    impl VersionedContentStore for DummyContentStore {
        fn version() -> StoreVersion {
            StoreVersion::IdIndexed
        }

        fn migrate_from(
            _content_type: ContentType,
            old_version: StoreVersion,
            _config: &PortalStorageConfig,
        ) -> Result<(), ContentStoreError> {
            Err(ContentStoreError::UnsupportedStoreMigration {
                old_version,
                new_version: Self::version(),
            })
        }

        fn create(
            _content_type: ContentType,
            _config: PortalStorageConfig,
            _metrics: StorageMetricsReporter,
        ) -> Result<Self, ContentStoreError> {
            Ok(Self {})
        }

        fn get_summary_info(&self) -> String {
            "DummyVersionedContentStore summary".to_string()
        }
    }
}
