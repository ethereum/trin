use crate::{
    error::ContentStoreError,
    sql::{
        CREATE_QUERY_DB_BEACON, CREATE_QUERY_DB_HISTORY, DROP_CONTENT_DATA_QUERY_DB,
        LC_UPDATE_CREATE_TABLE,
    },
    versioned::sql::STORE_INFO_CREATE_TABLE,
    DATABASE_NAME,
};
use sqlx::{query, sqlite::SqlitePoolOptions, SqlitePool};
use std::{
    fs::{self, OpenOptions},
    path::Path,
};
use tracing::info;

/// Helper function for opening a SQLite connection.
pub async fn setup_sql(node_data_dir: &Path) -> Result<SqlitePool, ContentStoreError> {
    let sql_path = node_data_dir.join(DATABASE_NAME);
    let sql_str_path = &sql_path.as_path().display().to_string()[..];
    info!(path = %sql_path.display(), "Setting up SqliteDB");

    let _ = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(sql_str_path);
    let pool = SqlitePoolOptions::new().connect(sql_str_path).await?;
    query(CREATE_QUERY_DB_HISTORY).execute(&pool).await?;
    query(CREATE_QUERY_DB_BEACON).execute(&pool).await?;
    query(LC_UPDATE_CREATE_TABLE).execute(&pool).await?;
    query(STORE_INFO_CREATE_TABLE).execute(&pool).await?;
    query(DROP_CONTENT_DATA_QUERY_DB).execute(&pool).await?;
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
