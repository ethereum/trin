// SQLite Statements

// NOTE: The indices `content_size_idx`, `content_id_short_idx` and `content_id_long_idx` weren't
// helpful mostly because they didn't have `network` column in them.
pub const CREATE_QUERY_DB: &str = "CREATE TABLE IF NOT EXISTS content_data (
                                content_id_long TEXT PRIMARY KEY,
                                content_id_short INTEGER NOT NULL,
                                content_key TEXT NOT NULL,
                                content_value TEXT NOT NULL,
                                network INTEGER NOT NULL DEFAULT 0,
                                content_size INTEGER
                            );
                            DROP INDEX IF EXISTS content_size_idx;
                            CREATE INDEX IF NOT EXISTS content_size_idx_2 ON content_data(network, content_size);
                            DROP INDEX IF EXISTS content_id_short_idx;
                            DROP INDEX IF EXISTS content_id_short_idx_2;
                            CREATE INDEX IF NOT EXISTS content_id_short_idx_3 ON content_data(network, content_id_short);
                            DROP INDEX IF EXISTS content_id_long_idx;
                            CREATE INDEX IF NOT EXISTS network_idx ON content_data(network);
                            CREATE INDEX IF NOT EXISTS content_key_idx ON content_data(content_key);";

pub const INSERT_QUERY_NETWORK: &str =
    "INSERT OR IGNORE INTO content_data (content_id_long, content_id_short, content_key, content_value, network, content_size)
                            VALUES (?1, ?2, ?3, ?4, ?5, ?6)";

pub const INSERT_LC_UPDATE_QUERY: &str =
    "INSERT OR IGNORE INTO lc_update (period, value, score, update_size)
                            VALUES (?1, ?2, ?3, ?4)";

pub const DELETE_QUERY_DB: &str = "DELETE FROM content_data
                            WHERE content_id_long = (?1)";

pub const XOR_FIND_FARTHEST_QUERY_NETWORK: &str = "SELECT
                                    content_id_long
                                    FROM content_data
                                    WHERE network = (?2)
                                    ORDER BY ((?1 | content_id_short) - (?1 & content_id_short)) DESC LIMIT 1";

pub const CONTENT_KEY_LOOKUP_QUERY_DB: &str =
    "SELECT content_key FROM content_data WHERE content_id_long = (?1) LIMIT 1";

pub const CONTENT_VALUE_LOOKUP_QUERY_DB: &str =
    "SELECT content_value FROM content_data WHERE content_id_long = (?1) LIMIT 1";

pub const TOTAL_DATA_SIZE_QUERY_DB: &str =
    "SELECT TOTAL(content_size) FROM content_data WHERE network = (?1)";

pub const TOTAL_ENTRY_COUNT_QUERY_NETWORK: &str =
    "SELECT COUNT(*) FROM content_data WHERE network = (?1)";

pub const PAGINATE_QUERY_DB: &str =
    "SELECT content_key FROM content_data ORDER BY content_key LIMIT :limit OFFSET :offset";

pub const CONTENT_SIZE_LOOKUP_QUERY_DB: &str =
    "SELECT content_size FROM content_data WHERE content_id_long = (?1)";

pub const LC_UPDATE_CREATE_TABLE: &str = "CREATE TABLE IF NOT EXISTS lc_update (
                                          period INTEGER PRIMARY KEY,
                                          value BLOB NOT NULL,
                                          score INTEGER NOT NULL,
                                          update_size INTEGER
                                      );
                                     CREATE INDEX IF NOT EXISTS update_size_idx ON lc_update(update_size);
                                     DROP INDEX IF EXISTS period_idx;";

pub const LC_UPDATE_LOOKUP_QUERY: &str = "SELECT value FROM lc_update WHERE period = (?1) LIMIT 1";

pub const LC_UPDATE_PERIOD_LOOKUP_QUERY: &str =
    "SELECT period FROM lc_update WHERE period = (?1) LIMIT 1";

pub const LC_UPDATE_TOTAL_SIZE_QUERY: &str = "SELECT TOTAL(update_size) FROM lc_update";
