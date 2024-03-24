use crate::{
    error::ContentStoreError,
    versioned::{
        id_indexed_v1::sql,
        usage_stats::{update_usage_stats, UsageStats},
        ContentType,
    },
};

use super::IdIndexedV1StoreConfig;

pub fn migrate_legacy_history_store(
    config: &IdIndexedV1StoreConfig,
) -> Result<(), ContentStoreError> {
    if config.content_type != ContentType::History {
        panic!("Can't migrate LegacyHistory store for non History content type.")
    }
    let content_type = &config.content_type;

    // Rename old table and drop old indicies (they can't be renamed).
    config.sql_connection_pool.get()?.execute_batch(&format!(
        "ALTER TABLE history RENAME TO {};
        DROP INDEX history_distance_short_idx;
        DROP INDEX history_content_size_idx;",
        sql::table_name(content_type)
    ))?;

    // Update usage stats
    let conn = config.sql_connection_pool.get()?;
    let usage_stats = conn.query_row(&sql::entry_count_and_size(content_type), [], |row| {
        Ok(UsageStats {
            entry_count: row.get("count")?,
            total_entry_size_bytes: row.get::<&str, f64>("used_capacity")?.round() as u64,
        })
    })?;
    update_usage_stats(&conn, content_type, &usage_stats)?;

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
        versioned::{
            create_store, usage_stats::get_usage_stats, IdIndexedV1Store, LegacyHistoryStore,
            VersionedContentStore,
        },
    };

    use super::*;

    const STORAGE_CAPACITY_MB: u64 = 10;

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
        let legacy_history_store = LegacyHistoryStore::new(config.clone())?;
        drop(legacy_history_store);

        // migrate
        let config = IdIndexedV1StoreConfig::new(ContentType::History, ProtocolId::History, config);
        migrate_legacy_history_store(&config)?;

        // make sure we can initialize new store and that it's empty
        IdIndexedV1Store::create(ContentType::History, config.clone())?;
        assert_eq!(
            get_usage_stats(&config.sql_connection_pool.get()?, &ContentType::History)?,
            UsageStats {
                entry_count: 0,
                total_entry_size_bytes: 0
            }
        );

        Ok(())
    }

    #[test]
    fn legacy_history_with_content() -> Result<()> {
        let (_temp_dir, config) =
            create_test_portal_storage_config_with_capacity(STORAGE_CAPACITY_MB)?;

        let mut key_value_map = HashMap::new();

        // initialize legacy store
        let mut legacy_history_store = LegacyHistoryStore::new(config.clone())?;
        for _ in 0..10 {
            let (key, value) = generate_key_value_with_content_size();
            legacy_history_store.store(&key, &value)?;
            key_value_map.insert(key, value);
        }
        drop(legacy_history_store);

        // migrate
        let config = IdIndexedV1StoreConfig::new(ContentType::History, ProtocolId::History, config);
        migrate_legacy_history_store(&config)?;

        // create IdIndexedV1Store and verify content
        let store = IdIndexedV1Store::create(ContentType::History, config)?;
        for (key, value) in key_value_map.into_iter() {
            assert_eq!(
                store.lookup_content_value(&key.content_id().into())?,
                Some(value),
            );
        }

        Ok(())
    }

    #[test]
    fn legacy_history_using_create_store() -> Result<()> {
        let (_temp_dir, config) =
            create_test_portal_storage_config_with_capacity(STORAGE_CAPACITY_MB)?;

        let mut key_value_map = HashMap::new();

        // initialize legacy store
        let mut legacy_history_store: LegacyHistoryStore = create_store(
            ContentType::History,
            config.clone(),
            config.sql_connection_pool.clone(),
        )?;
        for _ in 0..10 {
            let (key, value) = generate_key_value_with_content_size();
            legacy_history_store.store(&key, &value)?;
            key_value_map.insert(key, value);
        }
        drop(legacy_history_store);

        // create IdIndexedV1Store and verify content
        let config = IdIndexedV1StoreConfig::new(ContentType::History, ProtocolId::History, config);
        let store: IdIndexedV1Store = create_store(
            ContentType::History,
            config.clone(),
            config.sql_connection_pool.clone(),
        )?;
        for (key, value) in key_value_map.into_iter() {
            assert_eq!(
                store.lookup_content_value(&key.content_id().into())?,
                Some(value),
            );
        }

        Ok(())
    }
}
