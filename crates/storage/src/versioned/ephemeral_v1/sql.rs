use crate::versioned::ContentType;

/// The name of the sql table. The `eph1` stands for `ephemeral_v1`.
pub fn table_name(content_type: &ContentType) -> String {
    format!("eph1_{content_type}")
}

pub fn create_table(content_type: &ContentType) -> String {
    format!(
        "
        CREATE TABLE IF NOT EXISTS {0} (
            content_id BLOB PRIMARY KEY,
            content_key BLOB NOT NULL,
            content_value BLOB NOT NULL,
            type INTEGER NOT NULL,
            slot INTEGER NOT NULL,
            content_size INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS {0}_type_idx ON {0} (type);
        CREATE INDEX IF NOT EXISTS {0}_slot_idx ON {0} (slot);
        CREATE INDEX IF NOT EXISTS {0}_content_size_idx ON {0} (content_size);
        ",
        table_name(content_type)
    )
}

pub fn insert(content_type: &ContentType) -> String {
    format!(
        "
        INSERT OR IGNORE INTO {} (
            content_id,
            content_key,
            content_value,
            type,
            slot,
            content_size
        )
        VALUES (
            :content_id,
            :content_key,
            :content_value,
            :type,
            :slot,
            :content_size
        )",
        table_name(content_type)
    )
}

pub fn delete(content_type: &ContentType) -> String {
    format!(
        "DELETE FROM {}
        WHERE content_id = :content_id
        RETURNING content_size",
        table_name(content_type)
    )
}

pub fn lookup_key(content_type: &ContentType) -> String {
    format!(
        "SELECT content_key FROM {} WHERE content_id = :content_id LIMIT 1",
        table_name(content_type)
    )
}

pub fn lookup_value(content_type: &ContentType) -> String {
    format!(
        "SELECT content_value FROM {} WHERE content_id = :content_id LIMIT 1",
        table_name(content_type)
    )
}

pub fn entry_count_and_size(content_type: &ContentType) -> String {
    format!(
        "SELECT COUNT(*) as count, TOTAL(content_size) as used_capacity FROM {}",
        table_name(content_type)
    )
}

pub fn purge_by_slot(content_type: &ContentType) -> String {
    format!(
        "DELETE FROM {}
         WHERE slot < :slot",
        table_name(content_type)
    )
}
