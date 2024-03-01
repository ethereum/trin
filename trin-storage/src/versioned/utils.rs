use sqlx::{query, sqlite::SqliteRow, Row, SqlitePool};

use crate::error::ContentStoreError;

use super::{sql, store::VersionedContentStore, ContentType, StoreVersion};

/// Ensures that the correct version of the content store is used (by migrating the content if
/// that's not the case).
pub async fn create_store<S: VersionedContentStore>(
    content_type: ContentType,
    config: S::Config,
    sql_connection_pool: SqlitePool,
) -> Result<S, ContentStoreError> {
    let old_version = lookup_store_version(&content_type, &sql_connection_pool).await?;

    match old_version {
        Some(old_version) => {
            // Migrate if version doesn't match
            if S::version() != old_version {
                S::migrate_from(&content_type, old_version, &config)?;
                update_store_info(&content_type, S::version(), &sql_connection_pool).await?;
            }
        }
        None => {
            update_store_info(&content_type, S::version(), &sql_connection_pool).await?;
        }
    }

    S::create(content_type, config).await
}

async fn lookup_store_version(
    content_type: &ContentType,
    conn: &SqlitePool,
) -> Result<Option<StoreVersion>, ContentStoreError> {
    Ok(query(sql::STORE_INFO_LOOKUP)
        .bind(content_type.as_ref())
        .map(|row: SqliteRow| {
            let version: StoreVersion = row.get(0);
            version
        })
        .fetch_optional(conn)
        .await?)
}

async fn update_store_info(
    content_type: &ContentType,
    store_version: StoreVersion,
    conn: &SqlitePool,
) -> Result<(), ContentStoreError> {
    query(sql::STORE_INFO_UPDATE)
        .bind(content_type.as_ref())
        .bind(store_version.as_ref())
        .execute(conn)
        .await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod test {
    use anyhow::Result;
    use ethportal_api::jsonrpsee::tokio;

    use crate::{test_utils::create_test_portal_storage_config_with_capacity, PortalStorageConfig};

    use super::*;

    const STORAGE_CAPACITY_MB: u64 = 10;

    #[tokio::test]
    async fn lookup_no_store_version() -> Result<()> {
        let (_temp_dir, config) =
            create_test_portal_storage_config_with_capacity(STORAGE_CAPACITY_MB).await?;
        let conn = config.sql_connection_pool;

        assert_eq!(
            lookup_store_version(&ContentType::State, &conn).await?,
            None
        );
        Ok(())
    }

    #[tokio::test]
    async fn insert_store_verion() -> Result<()> {
        let (_temp_dir, config) =
            create_test_portal_storage_config_with_capacity(STORAGE_CAPACITY_MB).await?;
        let conn = config.sql_connection_pool;

        update_store_info(&ContentType::State, StoreVersion::IdIndexedV1, &conn).await?;

        assert_eq!(
            lookup_store_version(&ContentType::State, &conn).await?,
            Some(StoreVersion::IdIndexedV1)
        );
        Ok(())
    }

    #[tokio::test]
    async fn update_store_verion() -> Result<()> {
        let (_temp_dir, config) =
            create_test_portal_storage_config_with_capacity(STORAGE_CAPACITY_MB).await?;
        let conn = config.sql_connection_pool;

        // Set store version
        update_store_info(&ContentType::State, StoreVersion::IdIndexedLegacy, &conn).await?;
        assert_eq!(
            lookup_store_version(&ContentType::State, &conn).await?,
            Some(StoreVersion::IdIndexedLegacy)
        );

        // Update store version
        update_store_info(&ContentType::State, StoreVersion::IdIndexedV1, &conn).await?;
        assert_eq!(
            lookup_store_version(&ContentType::State, &conn).await?,
            Some(StoreVersion::IdIndexedV1)
        );

        Ok(())
    }

    #[tokio::test]
    async fn create_store_no_old_version() -> Result<()> {
        let (_temp_dir, config) =
            create_test_portal_storage_config_with_capacity(STORAGE_CAPACITY_MB).await?;
        let sql_connection_pool = config.sql_connection_pool.clone();

        // Should be successful
        create_store::<MockContentStore>(
            ContentType::State,
            config.clone(),
            sql_connection_pool.clone(),
        )
        .await?;

        assert_eq!(
            lookup_store_version(&ContentType::State, &sql_connection_pool).await?,
            Some(StoreVersion::IdIndexedV1)
        );

        Ok(())
    }

    #[tokio::test]
    async fn create_store_same_old_version() -> Result<()> {
        let (_temp_dir, config) =
            create_test_portal_storage_config_with_capacity(STORAGE_CAPACITY_MB).await?;
        let sql_connection_pool = config.sql_connection_pool.clone();

        update_store_info(
            &ContentType::State,
            StoreVersion::IdIndexedV1,
            &sql_connection_pool,
        )
        .await?;

        // Should be successful
        create_store::<MockContentStore>(ContentType::State, config.clone(), sql_connection_pool)
            .await?;

        assert_eq!(
            lookup_store_version(&ContentType::State, &config.sql_connection_pool).await?,
            Some(StoreVersion::IdIndexedV1)
        );

        Ok(())
    }

    #[tokio::test]
    #[should_panic = "UnsupportedStoreMigration"]
    async fn create_store_different_old_version() {
        let (_temp_dir, config) =
            create_test_portal_storage_config_with_capacity(STORAGE_CAPACITY_MB)
                .await
                .unwrap();
        let sql_connection_pool = config.sql_connection_pool.clone();

        update_store_info(
            &ContentType::State,
            StoreVersion::IdIndexedLegacy,
            &sql_connection_pool,
        )
        .await
        .unwrap();

        // Should panic - MockContentStore doesn't support migration.
        create_store::<MockContentStore>(ContentType::State, config, sql_connection_pool)
            .await
            .unwrap();
    }

    pub struct MockContentStore;

    impl VersionedContentStore for MockContentStore {
        type Config = PortalStorageConfig;

        fn version() -> StoreVersion {
            StoreVersion::IdIndexedV1
        }

        fn migrate_from(
            _content_type: &ContentType,
            old_version: StoreVersion,
            _config: &PortalStorageConfig,
        ) -> Result<(), ContentStoreError> {
            Err(ContentStoreError::UnsupportedStoreMigration {
                old_version,
                new_version: Self::version(),
            })
        }

        async fn create(
            _content_type: ContentType,
            _config: Self::Config,
        ) -> Result<Self, ContentStoreError> {
            Ok(Self {})
        }
    }
}
