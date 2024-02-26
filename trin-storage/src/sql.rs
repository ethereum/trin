// SQLite Statements
// History
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

// Beacon Specific SQL

pub const CREATE_QUERY_DB_BEACON: &str = "CREATE TABLE IF NOT EXISTS beacon (
    content_id blob PRIMARY KEY,
    content_key blob NOT NULL,
    content_value blob NOT NULL,
    content_size INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS beacon_content_size_idx ON beacon(content_size);
";

pub const INSERT_QUERY_BEACON: &str =
    "INSERT OR IGNORE INTO beacon (content_id, content_key, content_value, content_size)
                            VALUES (?1, ?2, ?3, ?4)";

pub const DELETE_QUERY_BEACON: &str = "DELETE FROM beacon
    WHERE content_id = (?1)";

pub const CONTENT_KEY_LOOKUP_QUERY_BEACON: &str =
    "SELECT content_key FROM beacon WHERE content_id = (?1) LIMIT 1";

pub const CONTENT_VALUE_LOOKUP_QUERY_BEACON: &str =
    "SELECT content_value FROM beacon WHERE content_id = (?1) LIMIT 1";

pub const TOTAL_DATA_SIZE_QUERY_BEACON: &str = "SELECT TOTAL(content_size) FROM beacon";

pub const TOTAL_ENTRY_COUNT_QUERY_BEACON: &str = "SELECT COUNT(*) FROM beacon";

pub const PAGINATE_QUERY_BEACON: &str =
    "SELECT content_key FROM beacon ORDER BY content_key LIMIT (?1) OFFSET (?2)";

pub const CONTENT_SIZE_LOOKUP_QUERY_BEACON: &str =
    "SELECT content_size FROM beacon WHERE content_id = (?1)";

pub const LC_UPDATE_CREATE_TABLE: &str = "CREATE TABLE IF NOT EXISTS lc_update (
        period INTEGER PRIMARY KEY,
        value BLOB NOT NULL,
        score INTEGER NOT NULL,
        update_size INTEGER
    );
    CREATE INDEX IF NOT EXISTS update_size_idx ON lc_update(update_size);
    DROP INDEX IF EXISTS period_idx;";

pub const INSERT_LC_UPDATE_QUERY: &str =
    "INSERT OR IGNORE INTO lc_update (period, value, score, update_size)
                      VALUES (?1, ?2, ?3, ?4)";

pub const LC_UPDATE_LOOKUP_QUERY: &str = "SELECT value FROM lc_update WHERE period = (?1) LIMIT 1";

pub const LC_UPDATE_PERIOD_LOOKUP_QUERY: &str =
    "SELECT period FROM lc_update WHERE period = (?1) LIMIT 1";

pub const LC_UPDATE_TOTAL_SIZE_QUERY: &str = "SELECT TOTAL(update_size) FROM lc_update";

// todo: remove this in the future
pub const DROP_CONTENT_DATA_QUERY_DB: &str = "DROP TABLE IF EXISTS content_data;";
