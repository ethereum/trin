// SQLite Statements

pub const CREATE_QUERY_DB_HISTORY: &str = "CREATE TABLE IF NOT EXISTS history (
    content_id blob PRIMARY KEY,
    content_key blob NOT NULL,
    content_value blob NOT NULL,
    distance_short INTEGER NOT NULL,
    content_size INTEGER NOT NULL
);
    CREATE INDEX IF NOT EXISTS history_distance_short_idx ON history(content_size);
    CREATE INDEX IF NOT EXISTS history_content_size_idx ON history(distance_short);
";

pub const INSERT_QUERY_HISTORY: &str =
    "INSERT OR IGNORE INTO history (content_id, content_key, content_value, distance_short, content_size)
                            VALUES (?1, ?2, ?3, ?4, ?5)";

pub const DELETE_QUERY_HISTORY: &str = "DELETE FROM history
                            WHERE content_id = (?1)";

pub const XOR_FIND_FARTHEST_QUERY_HISTORY: &str = "SELECT
                                    content_id
                                    FROM history
                                    ORDER BY distance_short DESC LIMIT 1";

pub const CONTENT_KEY_LOOKUP_QUERY_HISTORY: &str =
    "SELECT content_key FROM history WHERE content_id = (?1) LIMIT 1";

pub const CONTENT_VALUE_LOOKUP_QUERY_HISTORY: &str =
    "SELECT content_value FROM history WHERE content_id = (?1) LIMIT 1";

pub const TOTAL_DATA_SIZE_QUERY_HISTORY: &str = "SELECT TOTAL(content_size) FROM history";

pub const TOTAL_ENTRY_COUNT_QUERY_HISTORY: &str = "SELECT COUNT(*) FROM history";

pub const PAGINATE_QUERY_HISTORY: &str =
    "SELECT content_key FROM history ORDER BY content_key LIMIT (?1) OFFSET (?2)";

pub const CONTENT_SIZE_LOOKUP_QUERY_HISTORY: &str =
    "SELECT content_size FROM history WHERE content_id = (?1)";
