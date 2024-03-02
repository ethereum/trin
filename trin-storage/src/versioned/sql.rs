use super::ContentType;

pub const STORE_INFO_CREATE_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS store_info (
        content_type TEXT PRIMARY KEY,
        version TEXT NOT NULL
    )";

pub const STORE_INFO_UPDATE: &str = "
    INSERT OR REPLACE INTO store_info (content_type, version)
    VALUES (:content_type, :version)";

pub const STORE_INFO_LOOKUP: &str = "
    SELECT version
    FROM store_info
    WHERE content_type = :content_type
    LIMIT 1";

pub const USAGE_STATS_CREATE_TABLE: &str = "
    CREATE TABLE IF NOT EXISTS usage_stats (
        content_type TEXT PRIMARY KEY,
        count INTEGER NOT NULL,
        size INTEGER NOT NULL
    );";

pub const USAGE_STATS_UPDATE: &str = "
    INSERT OR REPLACE INTO usage_stats (content_type, count, size)
    VALUES (?1, ?2, ?3)";

pub const USAGE_STATS_LOOKUP: &str = "
    SELECT count, size
    FROM usage_stats
    WHERE content_type = (?1)
    LIMIT 1";

pub fn create_usage_stats_triggers(
    content_type: &ContentType,
    table_name: &str,
    entry_size_column: &str,
) -> String {
    format!(
        "
        CREATE TRIGGER IF NOT EXISTS {table_name}_on_insert_update_usage_stats_trigger
        AFTER INSERT ON {table_name}
        FOR EACH ROW
        BEGIN
            UPDATE usage_stats
            SET count = count + 1, size = size + NEW.{entry_size_column}
            WHERE content_type = '{content_type}';
        END;

        CREATE TRIGGER IF NOT EXISTS {table_name}_on_delete_update_usage_stats_trigger
        AFTER DELETE ON {table_name}
        FOR EACH ROW
        BEGIN
            UPDATE usage_stats
            SET count = count - 1, size = size - OLD.{entry_size_column}
            WHERE content_type = '{content_type}';
        END;

        CREATE TRIGGER IF NOT EXISTS {table_name}_on_update_update_usage_stats_trigger
        AFTER UPDATE ON {table_name}
        FOR EACH ROW
        BEGIN
            UPDATE usage_stats
            SET size = size - OLD.size + NEW.size
            WHERE content_type = '{content_type}';
        END;

        INSERT OR IGNORE INTO usage_stats (content_type, count, size)
        VALUES ('{content_type}', 0, 0);
        "
    )
}
