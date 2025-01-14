use std::path::Path;

use rocksdb::{Options, DB as RocksDB};
use tracing::info;

/// Helper function for opening a RocksDB connection for the radius-constrained db.
pub fn setup_rocksdb(path: &Path) -> anyhow::Result<RocksDB> {
    let rocksdb_path = path.join("rocksdb");
    info!(path = %rocksdb_path.display(), "Setting up RocksDB");

    let cache_size = 1024 * 1024 * 1024; // 1GB

    let mut db_opts = Options::default();
    db_opts.create_if_missing(true);
    db_opts.set_write_buffer_size(cache_size / 4);
    let mut factory = rocksdb::BlockBasedOptions::default();
    factory.set_block_cache(&rocksdb::Cache::new_lru_cache(cache_size / 2));
    db_opts.set_block_based_table_factory(&factory);

    // Set the max number of open files to 150. MacOs has a default limit of 256 open files per
    // process. This limit prevents issues with the OS running out of file descriptors.
    db_opts.set_max_open_files(150);
    Ok(RocksDB::open(&db_opts, rocksdb_path)?)
}
