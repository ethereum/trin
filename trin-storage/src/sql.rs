// SQLite Statements

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

/// Create the historical summaries table. Add CHECK constraint to ensure that only one row is
/// inserted.
pub const HISTORICAL_SUMMARIES_CREATE_TABLE: &str =
    "CREATE TABLE IF NOT EXISTS historical_summaries (
        ID INTEGER PRIMARY KEY CHECK (ID = 1),
        epoch INTEGER NOT NULL,
        value BLOB NOT NULL,
        update_size INTEGER
    );";

/// Query to insert or update the historical summaries table.
pub const INSERT_OR_REPLACE_HISTORICAL_SUMMARIES_QUERY: &str =
    "INSERT OR REPLACE INTO historical_summaries (id, epoch, value, update_size)
                      VALUES (?1, ?2, ?3, ?4)";

/// Query to get the historical summary that is greater than or equal to the given epoch.
pub const HISTORICAL_SUMMARIES_LOOKUP_QUERY: &str =
    "SELECT value FROM historical_summaries WHERE epoch >= (?1) LIMIT 1";

/// Query to get the epoch of the first historical summary that is greater than or equal to the
/// given epoch.
pub const HISTORICAL_SUMMARIES_EPOCH_LOOKUP_QUERY: &str =
    "SELECT epoch FROM historical_summaries WHERE epoch >= (?1) LIMIT 1";

// todo: remove this in the future
pub const DROP_USAGE_STATS_DB: &str = "DROP TABLE IF EXISTS usage_stats;";
