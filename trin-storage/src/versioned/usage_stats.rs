use r2d2::PooledConnection;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use trin_metrics::storage::StorageMetricsReporter;

use super::{sql, ContentType};

pub use sql::create_usage_stats_triggers;

/// Contains information about number and size of entries that is stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageStats {
    /// The total count of stored entries
    pub entry_count: u64,
    /// The total sum of sizes of stored entries
    pub total_entry_size_bytes: u64,
}

impl UsageStats {
    /// Returns the average entry size
    pub fn average_entry_size_bytes(&self) -> Option<f64> {
        if self.entry_count == 0 {
            Option::None
        } else {
            Option::Some(self.total_entry_size_bytes as f64 / self.entry_count as f64)
        }
    }

    /// Returns whether total entry size is above provided value
    pub fn is_above(&self, size_bytes: u64) -> bool {
        self.total_entry_size_bytes > size_bytes
    }

    /// Reports entry count and content data storage to the metrics reporter
    pub fn report_metrics(&self, metrics: &StorageMetricsReporter) {
        metrics.report_entry_count(self.entry_count);
        metrics.report_content_data_storage_bytes(self.total_entry_size_bytes as f64);
    }
}

/// Sets the usage stats for the given content type. This can be done during startup to make sure
/// that values are up to date.
#[allow(dead_code)] // this is currently not used but it can be useful
pub fn update_usage_stats(
    conn: &PooledConnection<SqliteConnectionManager>,
    content_type: &ContentType,
    usage_stats: &UsageStats,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        sql::USAGE_STATS_UPDATE,
        params![
            content_type.to_string(),
            usage_stats.entry_count,
            usage_stats.total_entry_size_bytes
        ],
    )?;
    Ok(())
}

/// Returns the usage stats for a given content type.
pub fn get_usage_stats(
    conn: &PooledConnection<SqliteConnectionManager>,
    content_type: &ContentType,
) -> Result<UsageStats, rusqlite::Error> {
    conn.query_row(
        sql::USAGE_STATS_LOOKUP,
        params![content_type.to_string()],
        |row| {
            Ok(UsageStats {
                entry_count: row.get("count")?,
                total_entry_size_bytes: row.get("size")?,
            })
        },
    )
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use r2d2::Pool;
    use tempfile::TempDir;

    use crate::utils::setup_sql;

    use super::*;

    const TABLE_NAME: &str = "test";
    const ENTRY_SIZE_COLUMN_NAME: &str = "size";
    const TEST_TABLE_CREATE: &str = "CREATE TABLE test (id TEXT NOT NULL, size INTEGER NOT NULL)";
    const TEST_TABLE_INSERT: &str = "INSERT INTO test (id, size) VALUES (?1, ?2)";
    const TEST_TABLE_UPDATE: &str = "UPDATE test SET size = (?2) WHERE id = (?1)";
    const TEST_TABLE_DELETE: &str = "DELETE FROM test WHERE id = (?1)";

    fn setup_for_tests(temp_dir: &TempDir) -> Pool<SqliteConnectionManager> {
        let pool = setup_sql(temp_dir.path()).unwrap();
        let conn = pool.get().unwrap();
        conn.execute_batch(TEST_TABLE_CREATE).unwrap();
        conn.execute_batch(&create_usage_stats_triggers(
            &ContentType::History,
            TABLE_NAME,
            ENTRY_SIZE_COLUMN_NAME,
        ))
        .unwrap();
        pool
    }

    fn assert_usage_stats(
        conn: &PooledConnection<SqliteConnectionManager>,
        expected_entry_count: u64,
        expected_total_entry_size_bytes: u64,
    ) -> Result<()> {
        assert_eq!(
            get_usage_stats(conn, &ContentType::History)?,
            UsageStats {
                entry_count: expected_entry_count,
                total_entry_size_bytes: expected_total_entry_size_bytes,
            }
        );
        Ok(())
    }

    #[test]
    fn average_entry_size_bytes() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let pool = setup_for_tests(&temp_dir);
        let conn = pool.get()?;

        assert_eq!(
            get_usage_stats(&conn, &ContentType::History)?.average_entry_size_bytes(),
            None
        );

        conn.execute(TEST_TABLE_INSERT, params!["a", 100])?;
        assert_eq!(
            get_usage_stats(&conn, &ContentType::History)?.average_entry_size_bytes(),
            Some(100.0)
        );

        conn.execute(TEST_TABLE_INSERT, params!["b", 200])?;
        assert_eq!(
            get_usage_stats(&conn, &ContentType::History)?.average_entry_size_bytes(),
            Some(150.0)
        );

        conn.execute(TEST_TABLE_INSERT, params!["c", 300])?;
        assert_eq!(
            get_usage_stats(&conn, &ContentType::History)?.average_entry_size_bytes(),
            Some(200.0)
        );

        Ok(())
    }

    #[test]
    fn empty() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let pool = setup_for_tests(&temp_dir);
        let conn = pool.get()?;
        assert_usage_stats(&conn, 0, 0)?;

        Ok(())
    }

    #[test]
    fn insert_simple() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let pool = setup_for_tests(&temp_dir);
        let conn = pool.get()?;

        conn.execute(TEST_TABLE_INSERT, params!["a", 100])?;
        assert_usage_stats(&conn, 1, 100)?;

        Ok(())
    }

    #[test]
    fn insert_multiple() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let pool = setup_for_tests(&temp_dir);
        let conn = pool.get()?;

        conn.execute(TEST_TABLE_INSERT, params!["a", 100])?;
        assert_usage_stats(&conn, 1, 100)?;

        conn.execute(TEST_TABLE_INSERT, params!["b", 200])?;
        assert_usage_stats(&conn, 2, 300)?;

        conn.execute(TEST_TABLE_INSERT, params!["c", 300])?;
        assert_usage_stats(&conn, 3, 600)?;

        Ok(())
    }

    #[test]
    fn delete_simple() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let pool = setup_for_tests(&temp_dir);
        let conn = pool.get()?;

        conn.execute(TEST_TABLE_INSERT, params!["a", 100])?;
        assert_usage_stats(&conn, 1, 100)?;

        conn.execute(TEST_TABLE_DELETE, params!["a"])?;
        assert_usage_stats(&conn, 0, 0)?;

        Ok(())
    }

    #[test]
    fn delete_multiple() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let pool = setup_for_tests(&temp_dir);
        let conn = pool.get()?;

        conn.execute(TEST_TABLE_INSERT, params!["a", 100])?;
        conn.execute(TEST_TABLE_INSERT, params!["b", 200])?;
        conn.execute(TEST_TABLE_INSERT, params!["c", 300])?;
        assert_usage_stats(&conn, 3, 600)?;

        conn.execute(TEST_TABLE_DELETE, params!["b"])?;
        assert_usage_stats(&conn, 2, 400)?;

        conn.execute(TEST_TABLE_DELETE, params!["a"])?;
        assert_usage_stats(&conn, 1, 300)?;

        conn.execute(TEST_TABLE_DELETE, params!["c"])?;
        assert_usage_stats(&conn, 0, 0)?;

        Ok(())
    }

    #[test]
    fn update_simple() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let pool = setup_for_tests(&temp_dir);
        let conn = pool.get()?;

        conn.execute(TEST_TABLE_INSERT, params!["a", 100])?;
        assert_usage_stats(&conn, 1, 100)?;

        conn.execute(TEST_TABLE_UPDATE, params!["a", 200])?;
        assert_usage_stats(&conn, 1, 200)?;

        Ok(())
    }

    #[test]
    fn update_comples() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let pool = setup_for_tests(&temp_dir);
        let conn = pool.get()?;

        conn.execute(TEST_TABLE_INSERT, params!["a", 100])?;
        conn.execute(TEST_TABLE_INSERT, params!["b", 200])?;
        conn.execute(TEST_TABLE_INSERT, params!["c", 300])?;
        assert_usage_stats(&conn, 3, 600)?;

        conn.execute(TEST_TABLE_UPDATE, params!["b", 500])?;
        assert_usage_stats(&conn, 3, 900)?;
        conn.execute(TEST_TABLE_UPDATE, params!["c", 100])?;
        assert_usage_stats(&conn, 3, 700)?;

        Ok(())
    }

    #[test]
    fn update_usage_stats_on_empty() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let pool = setup_for_tests(&temp_dir);
        let conn = pool.get()?;

        let usage_stats = UsageStats {
            entry_count: 1,
            total_entry_size_bytes: 100,
        };
        update_usage_stats(&conn, &ContentType::History, &usage_stats)?;
        assert_eq!(get_usage_stats(&conn, &ContentType::History)?, usage_stats);

        Ok(())
    }

    #[test]
    fn update_usage_stats_after_insert() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let pool = setup_for_tests(&temp_dir);
        let conn = pool.get()?;

        conn.execute(TEST_TABLE_INSERT, params!["a", 100])?;
        assert_usage_stats(&conn, 1, 100)?;

        let usage_stats = UsageStats {
            entry_count: 3,
            total_entry_size_bytes: 1000,
        };
        update_usage_stats(&conn, &ContentType::History, &usage_stats)?;
        assert_eq!(get_usage_stats(&conn, &ContentType::History)?, usage_stats);

        Ok(())
    }
}
