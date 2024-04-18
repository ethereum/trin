use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use tracing::{debug, info};

use crate::{
    error::ContentStoreError,
    versioned::{id_indexed_v1, sql::delete_usage_stats_triggers, ContentType},
};

pub fn migrate_id_indexed_store(
    sql_connection_pool: &Pool<SqliteConnectionManager>,
) -> Result<(), ContentStoreError> {
    info!("Migration started");
    let old_table_name = id_indexed_v1::sql::table_name(&ContentType::History);

    // Rename table
    debug!("Renaming table: {old_table_name} -> history");
    sql_connection_pool.get()?.execute_batch(&format!(
        "ALTER TABLE {} RENAME TO history;",
        old_table_name
    ))?;

    // Drop old indicies (they can't be renamed)
    debug!("Dropping old indices");
    sql_connection_pool.get()?.execute_batch(&format!(
        "DROP INDEX {old_table_name}_distance_short_idx;
        DROP INDEX {old_table_name}_content_size_idx;"
    ))?;

    // Delete usage stats
    debug!("Deleting usage stats");
    sql_connection_pool
        .get()?
        .execute_batch(&delete_usage_stats_triggers(
            &ContentType::History,
            &old_table_name,
        ))?;

    info!("Migration finished");
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
        versioned::{create_store, IdIndexedV1StoreConfig, LegacyHistoryStore},
    };

    use self::id_indexed_v1::IdIndexedV1Store;

    use super::*;

    #[test]
    fn legacy_history_using_create_store() -> Result<()> {
        let (_temp_dir, config) =
            create_test_portal_storage_config_with_capacity(/* capacity_mb= */ 10)?;

        let mut key_value_map = HashMap::new();

        // initialize IdIndexedV1Store
        let mut id_indexed_v1_store: IdIndexedV1Store = create_store(
            ContentType::History,
            IdIndexedV1StoreConfig::new(ContentType::History, ProtocolId::History, config.clone()),
            config.sql_connection_pool.clone(),
        )?;
        for _ in 0..10 {
            let key = IdentityContentKey::random();
            let value = generate_random_bytes(rand::thread_rng().gen_range(100..200));
            id_indexed_v1_store.insert(&key, value.clone())?;
            key_value_map.insert(key, value);
        }
        drop(id_indexed_v1_store);

        // create legacy store and verify content
        let legacy_history_store: LegacyHistoryStore = create_store(
            ContentType::History,
            config.clone(),
            config.sql_connection_pool.clone(),
        )?;
        for (key, value) in key_value_map.into_iter() {
            assert_eq!(
                legacy_history_store.lookup_content_value(key.content_id())?,
                Some(value),
            );
        }

        Ok(())
    }
}
