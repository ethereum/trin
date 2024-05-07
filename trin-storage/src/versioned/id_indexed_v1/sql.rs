use crate::versioned::ContentType;

/// The name of the sql table. The `ii1` stands for `id_indexed_v1`.
pub fn table_name(content_type: &ContentType) -> String {
    format!("ii1_{content_type}")
}

pub fn create_table(content_type: &ContentType) -> String {
    format!(
        "
        CREATE TABLE IF NOT EXISTS {0} (
            content_id BLOB PRIMARY KEY,
            content_key BLOB NOT NULL,
            content_value BLOB NOT NULL,
            distance_short INTEGER NOT NULL,
            content_size INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS {0}_distance_short_idx ON {0} (distance_short);
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
            distance_short,
            content_size
        )
        VALUES (
            :content_id,
            :content_key,
            :content_value,
            :distance_short,
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

pub fn delete_farthest(content_type: &ContentType) -> String {
    format!(
        "DELETE FROM {0}
        WHERE rowid IN (
            SELECT rowid
            FROM {0}
            ORDER BY distance_short DESC
            LIMIT :limit
        )
        RETURNING content_size",
        table_name(content_type)
    )
}

pub fn lookup_farthest(content_type: &ContentType) -> String {
    format!(
        "SELECT content_id, distance_short FROM {}
        ORDER BY distance_short DESC
        LIMIT :limit",
        table_name(content_type)
    )
}

pub fn paginate(content_type: &ContentType) -> String {
    format!(
        "SELECT content_key FROM {}
        ORDER BY content_key
        LIMIT :limit
        OFFSET :offset",
        table_name(content_type)
    )
}

pub fn entry_count_and_size(content_type: &ContentType) -> String {
    format!(
        "SELECT COUNT(*) as count, TOTAL(content_size) as used_capacity FROM {}",
        table_name(content_type)
    )
}
