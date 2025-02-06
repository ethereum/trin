// SQLite Statements

// Beacon Specific SQL

pub const LC_BOOTSTRAP_CREATE_TABLE: &str = "CREATE TABLE IF NOT EXISTS lc_bootstrap (
    block_root blob PRIMARY KEY,
    value blob NOT NULL,
    slot INTEGER NOT NULL,
    content_size INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS bootstrap_slot_idx ON lc_bootstrap(slot);
CREATE INDEX IF NOT EXISTS bootstrap_content_size_idx ON lc_bootstrap(content_size);
";

pub const INSERT_BOOTSTRAP_QUERY: &str =
    "INSERT OR IGNORE INTO lc_bootstrap (block_root, value, slot, content_size)
                            VALUES (?1, ?2, ?3, ?4)";

pub const LC_BOOTSTRAP_ROOT_LOOKUP_QUERY: &str =
    "SELECT block_root FROM lc_bootstrap WHERE block_root = (?1) LIMIT 1";

pub const LC_BOOTSTRAP_LOOKUP_QUERY: &str =
    "SELECT value FROM lc_bootstrap WHERE block_root = (?1) LIMIT 1";

/// Query to get the block root of the latest bootstrap record.
pub const LC_BOOTSTRAP_LATEST_BLOCK_ROOT_QUERY: &str =
    "SELECT block_root FROM lc_bootstrap ORDER BY slot DESC LIMIT 1";

/// Total beacon data size is the combination of lc_bootstrap, lc_update and historical_summaries
/// tables
pub const TOTAL_DATA_SIZE_QUERY_BEACON: &str = "SELECT
    (SELECT TOTAL(content_size) FROM lc_bootstrap) +
    (SELECT TOTAL(update_size) FROM lc_update) +
    (SELECT TOTAL(update_size) FROM historical_summaries) AS total_data_size;";

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

/// Benchmarking with WAL mode enabled 1.4 to 1.9x's Trin performance
pub const ENABLE_WAL_MODE: &str = "PRAGMA journal_mode = WAL;PRAGMA synchronous = NORMAL;";
