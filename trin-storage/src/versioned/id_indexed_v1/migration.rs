use tracing::{debug, info};

use crate::{
    error::ContentStoreError,
    versioned::{id_indexed_v1::sql, ContentType},
};

use super::IdIndexedV1StoreConfig;

pub fn migrate_legacy_history_store(
    config: &IdIndexedV1StoreConfig,
) -> Result<(), ContentStoreError> {
    if config.content_type != ContentType::History {
        panic!("Can't migrate LegacyHistory store for non History content type.")
    }
    let content_type = &config.content_type;

    info!(content_type = %content_type, "Migration started");

    let new_table_name = sql::table_name(content_type);

    // Rename table
    debug!(content_type = %content_type, "Renaming table: history -> {new_table_name}");
    config.sql_connection_pool.get()?.execute_batch(&format!(
        "ALTER TABLE history RENAME TO {};",
        new_table_name
    ))?;

    // Drop old indicies (they can't be renamed)
    debug!(content_type = %content_type, "Dropping old indices");
    config.sql_connection_pool.get()?.execute_batch(
        "DROP INDEX history_distance_short_idx;
        DROP INDEX history_content_size_idx;",
    )?;

    // Create new indicies
    debug!(content_type = %content_type, "Creating new indices");
    config.sql_connection_pool.get()?.execute_batch(&format!(
        "CREATE INDEX IF NOT EXISTS {0}_distance_short_idx ON {0} (distance_short);
        CREATE INDEX IF NOT EXISTS {0}_content_size_idx ON {0} (content_size);",
        new_table_name
    ))?;

    info!(content_type = %content_type, "Migration finished");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use anyhow::Result;
    use ethportal_api::{types::portal_wire::ProtocolId, IdentityContentKey, OverlayContentKey};
    use rand::Rng;

    use crate::{
        test_utils::{create_test_portal_storage_config_with_capacity, generate_random_bytes},
        versioned::{usage_stats::UsageStats, IdIndexedV1Store, VersionedContentStore},
    };

    use super::*;

    const STORAGE_CAPACITY_MB: u64 = 10;

    mod legacy_history {
        // Minimal code needed to test migration (since original code is deleted)

        use rusqlite::params;

        use super::*;
        use crate::PortalStorageConfig;

        const CREATE_QUERY_DB_HISTORY: &str = "CREATE TABLE IF NOT EXISTS history (
            content_id blob PRIMARY KEY,
            content_key blob NOT NULL,
            content_value blob NOT NULL,
            distance_short INTEGER NOT NULL,
            content_size INTEGER NOT NULL
        );
            CREATE INDEX IF NOT EXISTS history_distance_short_idx ON history(content_size);
            CREATE INDEX IF NOT EXISTS history_content_size_idx ON history(distance_short);
        ";

        const INSERT_QUERY_HISTORY: &str =
            "INSERT OR IGNORE INTO history (content_id, content_key, content_value, distance_short, content_size)
                                    VALUES (?1, ?2, ?3, ?4, ?5)";

        pub fn create_store(config: &PortalStorageConfig) -> Result<()> {
            config
                .sql_connection_pool
                .get()?
                .execute_batch(CREATE_QUERY_DB_HISTORY)?;
            Ok(())
        }

        pub fn store(
            config: &PortalStorageConfig,
            key: &impl OverlayContentKey,
            value: &Vec<u8>,
        ) -> Result<()> {
            let content_id = key.content_id();
            let key = key.to_bytes();
            let distance_u32 = config
                .distance_fn
                .distance(&config.node_id, &content_id)
                .big_endian_u32();
            let content_size = content_id.len() + key.len() + value.len();
            config.sql_connection_pool.get()?.execute(
                INSERT_QUERY_HISTORY,
                params![
                    content_id.as_slice(),
                    key,
                    value,
                    distance_u32,
                    content_size
                ],
            )?;
            Ok(())
        }
    }

    fn generate_key_value_with_content_size() -> (IdentityContentKey, Vec<u8>) {
        let key = IdentityContentKey::random();
        let value = generate_random_bytes(rand::thread_rng().gen_range(100..200));
        (key, value)
    }

    #[test]
    fn legacy_history_empty() -> Result<()> {
        let (_temp_dir, config) =
            create_test_portal_storage_config_with_capacity(STORAGE_CAPACITY_MB)?;

        // initialize legacy store
        legacy_history::create_store(&config)?;

        // migrate
        let config = IdIndexedV1StoreConfig::new(ContentType::History, ProtocolId::History, config);
        migrate_legacy_history_store(&config)?;

        // make sure we can initialize new store and that it's empty
        let store: IdIndexedV1Store<IdentityContentKey> =
            IdIndexedV1Store::create(ContentType::History, config.clone())?;
        assert_eq!(store.usage_stats(), UsageStats::default(),);

        Ok(())
    }

    #[test]
    fn legacy_history_with_content() -> Result<()> {
        let (_temp_dir, config) =
            create_test_portal_storage_config_with_capacity(STORAGE_CAPACITY_MB)?;

        let mut key_value_map = HashMap::new();

        // initialize legacy store
        legacy_history::create_store(&config)?;
        for _ in 0..10 {
            let (key, value) = generate_key_value_with_content_size();
            legacy_history::store(&config, &key, &value)?;
            key_value_map.insert(key, value);
        }

        // migrate
        let config = IdIndexedV1StoreConfig::new(ContentType::History, ProtocolId::History, config);
        migrate_legacy_history_store(&config)?;

        // create IdIndexedV1Store and verify content
        let store: IdIndexedV1Store<IdentityContentKey> =
            IdIndexedV1Store::create(ContentType::History, config)?;
        for (key, value) in key_value_map.into_iter() {
            assert_eq!(
                store.lookup_content_value(&key.content_id().into())?,
                Some(value),
            );
        }

        Ok(())
    }
}
