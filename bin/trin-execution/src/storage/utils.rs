use std::path::Path;

use redb::{Database as ReDB, Error};
use tracing::info;


/// Helper function for opening a ReDB database at the specified path.
pub fn setup_redb(path: &Path) -> Result<ReDB, Error> {
    let redb_path = path.join("redb");
    info!(path = %redb_path.display(), "Setting up ReDB");

    let db = if redb_path.exists() {
        ReDB::open(redb_path)?
    } else {
        ReDB::create(redb_path)?
    };

    Ok(db)
}