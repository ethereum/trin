use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{named_params, OptionalExtension};

use crate::error::ContentStoreError;

use super::{sql, store::VersionedContentStore, ContentType, StoreVersion};

/// Ensures that the correct version of the content store is used (by migrating the content if
/// that's not the case).
pub fn create_store<S: VersionedContentStore>(
    content_type: ContentType,
    config: S::Config,
    sql_connection_pool: Pool<SqliteConnectionManager>,
) -> Result<S, ContentStoreError> {
    let old_version = get_store_version(&content_type, &sql_connection_pool.get()?)?;

    match old_version {
        Some(old_version) => {
            // Migrate if version doesn't match
            if S::version() != old_version {
                S::migrate_from(&content_type, old_version, &config)?;
                update_store_info(&content_type, S::version(), &sql_connection_pool.get()?)?;
            }
        }
        None => {
            update_store_info(&content_type, S::version(), &sql_connection_pool.get()?)?;
        }
    }

    S::create(content_type, config)
}

fn get_store_version(
    content_type: &ContentType,
    conn: &PooledConnection<SqliteConnectionManager>,
) -> Result<Option<StoreVersion>, ContentStoreError> {
    let version = conn
        .query_row(
            sql::STORE_INFO_LOOKUP,
            named_params! { ":content_type": content_type.as_ref() },
            |row| row.get::<&str, StoreVersion>("version"),
        )
        .optional()?;

    match version {
        Some(_) => Ok(version),
        None => get_default_store_version(content_type, conn),
    }
}

fn get_default_store_version(
    content_type: &ContentType,
    conn: &PooledConnection<SqliteConnectionManager>,
) -> Result<Option<StoreVersion>, ContentStoreError> {
    match content_type {
        ContentType::History => {
            let exists = conn
                .prepare(sql::TABLE_EXISTS)?
                .exists(named_params! {":table_name": "history"})?;
            if exists {
                Ok(Some(StoreVersion::LegacyHistory))
            } else {
                Ok(None)
            }
        }
        _ => Ok(None),
    }
}

fn update_store_info(
    content_type: &ContentType,
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
pub mod test {
    use anyhow::Result;

    use crate::{test_utils::create_test_portal_storage_config_with_capacity, PortalStorageConfig};

    use super::*;

    const STORAGE_CAPACITY_MB: u64 = 10;

    #[test]
    fn get_store_version_missing() -> Result<()> {
        let (_temp_dir, config) =
            create_test_portal_storage_config_with_capacity(STORAGE_CAPACITY_MB)?;
        let conn = config.sql_connection_pool.get()?;

        assert_eq!(get_store_version(&ContentType::History, &conn)?, None);
        Ok(())
    }

    #[test]
    fn get_store_version_default_history() -> Result<()> {
        let (_temp_dir, config) =
            create_test_portal_storage_config_with_capacity(STORAGE_CAPACITY_MB)?;
        let conn = config.sql_connection_pool.get()?;

        let create_dummy_history_table_sql = "CREATE TABLE history (content_id blob PRIMARY KEY);";
        conn.execute(create_dummy_history_table_sql, [])?;

        assert_eq!(
            get_store_version(&ContentType::History, &conn)?,
            Some(StoreVersion::LegacyHistory)
        );
        Ok(())
    }

    #[test]
    fn insert_store_verion() -> Result<()> {
        let (_temp_dir, config) =
            create_test_portal_storage_config_with_capacity(STORAGE_CAPACITY_MB)?;
        let conn = config.sql_connection_pool.get()?;

        update_store_info(&ContentType::State, StoreVersion::IdIndexedV1, &conn)?;

        assert_eq!(
            get_store_version(&ContentType::State, &conn)?,
            Some(StoreVersion::IdIndexedV1)
        );
        Ok(())
    }

    #[test]
    fn update_store_verion() -> Result<()> {
        let (_temp_dir, config) =
            create_test_portal_storage_config_with_capacity(STORAGE_CAPACITY_MB)?;
        let conn = config.sql_connection_pool.get()?;

        // Set store version
        update_store_info(&ContentType::State, StoreVersion::LegacyHistory, &conn)?;
        assert_eq!(
            get_store_version(&ContentType::State, &conn)?,
            Some(StoreVersion::LegacyHistory)
        );

        // Update store version
        update_store_info(&ContentType::State, StoreVersion::IdIndexedV1, &conn)?;
        assert_eq!(
            get_store_version(&ContentType::State, &conn)?,
            Some(StoreVersion::IdIndexedV1)
        );

        Ok(())
    }

    #[test]
    fn create_store_no_old_version() -> Result<()> {
        let (_temp_dir, config) =
            create_test_portal_storage_config_with_capacity(STORAGE_CAPACITY_MB)?;
        let sql_connection_pool = config.sql_connection_pool.clone();

        // Should be successful
        create_store::<MockContentStore>(
            ContentType::State,
            config.clone(),
            sql_connection_pool.clone(),
        )?;

        assert_eq!(
            get_store_version(&ContentType::State, &sql_connection_pool.get()?)?,
            Some(StoreVersion::IdIndexedV1)
        );

        Ok(())
    }

    #[test]
    fn create_store_same_old_version() -> Result<()> {
        let (_temp_dir, config) =
            create_test_portal_storage_config_with_capacity(STORAGE_CAPACITY_MB)?;
        let sql_connection_pool = config.sql_connection_pool.clone();

        update_store_info(
            &ContentType::State,
            StoreVersion::IdIndexedV1,
            &sql_connection_pool.get()?,
        )?;

        // Should be successful
        create_store::<MockContentStore>(ContentType::State, config.clone(), sql_connection_pool)?;

        assert_eq!(
            get_store_version(&ContentType::State, &config.sql_connection_pool.get()?)?,
            Some(StoreVersion::IdIndexedV1)
        );

        Ok(())
    }

    #[test]
    #[should_panic = "UnsupportedStoreMigration"]
    fn create_store_different_old_version() {
        let (_temp_dir, config) =
            create_test_portal_storage_config_with_capacity(STORAGE_CAPACITY_MB).unwrap();
        let sql_connection_pool = config.sql_connection_pool.clone();

        update_store_info(
            &ContentType::History,
            StoreVersion::LegacyHistory,
            &sql_connection_pool.get().unwrap(),
        )
        .unwrap();

        // Should panic - MockContentStore doesn't support migration.
        create_store::<MockContentStore>(ContentType::History, config, sql_connection_pool)
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

        fn create(
            _content_type: ContentType,
            _config: PortalStorageConfig,
        ) -> Result<Self, ContentStoreError> {
            Ok(Self {})
        }
    }
}
