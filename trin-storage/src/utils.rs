use crate::{
    error::ContentStoreError,
    sql::{
        CONTENT_VALUE_LOOKUP_QUERY_DB, CREATE_QUERY_DB, INSERT_QUERY_NETWORK,
        LC_UPDATE_CREATE_TABLE,
    },
    DATABASE_NAME,
};
use anyhow::Error;
use ethportal_api::{
    types::distance::Distance,
    utils::bytes::{hex_decode, hex_encode},
};
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use std::{fs, path::Path};
use tracing::info;

/// Helper function for opening a SQLite connection.
pub fn setup_sql(node_data_dir: &Path) -> Result<Pool<SqliteConnectionManager>, ContentStoreError> {
    let sql_path = node_data_dir.join(DATABASE_NAME);
    info!(path = %sql_path.display(), "Setting up SqliteDB");

    let manager = SqliteConnectionManager::file(sql_path);
    let pool = Pool::new(manager)?;
    pool.get()?.execute_batch(CREATE_QUERY_DB)?;
    pool.get()?.execute_batch(LC_UPDATE_CREATE_TABLE)?;
    Ok(pool)
}

/// Internal method used to measure on-disk storage usage.
pub fn get_total_size_of_directory_in_bytes(
    path: impl AsRef<Path>,
) -> Result<u64, ContentStoreError> {
    let metadata = match fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(_) => {
            return Ok(0);
        }
    };
    let mut size = metadata.len();

    if metadata.is_dir() {
        for entry in fs::read_dir(&path)? {
            let dir = entry?;
            let path_string = match dir.path().into_os_string().into_string() {
                Ok(path_string) => path_string,
                Err(err) => {
                    let err = format!(
                        "Unable to convert path {:?} into string {:?}",
                        path.as_ref(),
                        err
                    );
                    return Err(ContentStoreError::Database(err));
                }
            };
            size += get_total_size_of_directory_in_bytes(path_string)?;
        }
    }

    Ok(size)
}

/// Internal method for looking up a content value by its content id
pub fn lookup_content_value(
    id: [u8; 32],
    conn: PooledConnection<SqliteConnectionManager>,
) -> Result<Result<Option<Vec<u8>>, Error>, Error> {
    let mut query = conn.prepare(CONTENT_VALUE_LOOKUP_QUERY_DB)?;
    let id = id.to_vec();
    let result: Result<Vec<Vec<u8>>, ContentStoreError> = query
        .query_map([id], |row| {
            let row: String = row.get(0)?;
            Ok(row)
        })?
        .map(|row| hex_decode(row?.as_str()).map_err(ContentStoreError::ByteUtilsError))
        .collect();

    Ok(match result?.first() {
        Some(val) => Ok(Some(val.to_vec())),
        None => Ok(None),
    })
}

/// Converts 4 most significant bytes of a byte slice to a u32.
pub fn byte_slice_to_u32(slice: &[u8; 32]) -> u32 {
    let mut be_bytes = [0u8; 4];
    be_bytes.copy_from_slice(&slice[..4]);
    u32::from_be_bytes(be_bytes)
}

/// Converts 4 most significant bytes of distance to a u32.
pub fn distance_to_u32(distance: &Distance) -> u32 {
    byte_slice_to_u32(&distance.big_endian())
}

/// Inserts a content  into the database.
pub fn insert_value(
    conn: PooledConnection<SqliteConnectionManager>,
    content_id: &[u8; 32],
    content_key: &String,
    value: &Vec<u8>,
    network_id: u8,
) -> Result<usize, ContentStoreError> {
    let content_id_as_u32: u32 = byte_slice_to_u32(content_id);
    let value_size = value.len();
    if content_key.starts_with("0x") {
        return Err(ContentStoreError::InvalidData {
            message: "Content key should not start with 0x".to_string(),
        });
    }
    match conn.execute(
        INSERT_QUERY_NETWORK,
        params![
            content_id.to_vec(),
            content_id_as_u32,
            content_key,
            hex_encode(value),
            network_id,
            value_size
        ],
    ) {
        Ok(result) => Ok(result),
        Err(err) => Err(err.into()),
    }
}
