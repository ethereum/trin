use rusqlite::{params, Connection};
use serde_json::{json, Value};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

use crate::portalnet::storage::PortalStorage;

/// Params for SqlHandler operations without any params
#[derive(Debug)]
pub struct EmptyParams {}

/// Params for FindFarthest operation
#[derive(Debug)]
pub struct FindFarthestParams {
    pub node_id: Vec<u8>,
}

/// Params for Insert operation
#[derive(Debug)]
pub struct InsertParams {
    pub content_id: Vec<u8>,
    pub content_id_as_u32: u32,
    pub content_key: String,
    pub value_size: u32,
}

/// Params for Remove operation
#[derive(Debug)]
pub struct RemoveParams {
    pub content_id: Vec<u8>,
}

/// Various types of permitted operations on metadata (sqlite) database
#[derive(Debug)]
pub enum SqlQuery {
    Create(EmptyParams),
    Insert(InsertParams),
    Remove(RemoveParams),
    TotalStorage(EmptyParams),
    FindFarthest(FindFarthestParams),
}

/// Struct to encapsulate R/W requests to metadata (sqlite) database
#[derive(Debug)]
pub struct SqlTransaction {
    pub query_type: SqlQuery,
    pub resp: oneshot::Sender<Result<Value, SqlHandlerError>>,
}

/// Data object to handle R/W requests to metadata (sqlite) database from 1 or more threads.
pub struct SqlHandler {
    pub conn: Connection,
    pub sql_rx: mpsc::Receiver<SqlTransaction>,
}

/// Error type returned in a Result by any failable public SqlHandler methods.
#[derive(Debug, Error)]
pub enum SqlHandlerError {
    #[error("Sql Error")]
    Sql(#[from] rusqlite::Error),

    #[error("Transport Error")]
    Tokio(#[from] mpsc::error::SendError<SqlTransaction>),

    #[error("SqlHandler received invalid parameters for {request_type:?} request.")]
    InvalidParams { request_type: String },

    #[error("SqlHandler failed to execute {request_type:?} request.")]
    FailedExecution { request_type: String },

    #[error("SqlHandler failed to prepare {request_type:?} request.")]
    FailedPrepare { request_type: String },

    #[error("Timeout while communicating with the SqlHandler, verify that it's running.")]
    Timeout,
}

impl SqlHandler {
    pub fn new(
        conn: Connection,
        sql_rx: mpsc::Receiver<SqlTransaction>,
    ) -> Result<Self, SqlHandlerError> {
        let handler = Self { conn, sql_rx };
        handler.create()?;
        Ok(handler)
    }

    /// Long-running process to handle various R/W operations from multiple threads
    pub async fn process_sql_requests(mut self) {
        while let Some(request) = self.sql_rx.recv().await {
            let response = match request.query_type {
                SqlQuery::Create(_params) => self.create(),
                SqlQuery::Insert(params) => self.insert(params),
                SqlQuery::Remove(params) => self.remove(params),
                SqlQuery::TotalStorage(_params) => self.total_storage(),
                SqlQuery::FindFarthest(params) => self.find_farthest(params),
            };
            let _ = request.resp.send(response);
        }
    }

    /// Create the metadata (sqlite) database
    fn create(&self) -> Result<Value, SqlHandlerError> {
        match self.conn.execute(CREATE_QUERY, []) {
            Ok(_) => Ok(Value::Null),
            Err(_) => Err(SqlHandlerError::FailedExecution {
                request_type: "Create".to_string(),
            }),
        }
    }

    /// Remove a ContentID from the metadata (sqlite) database
    fn remove(&self, params: RemoveParams) -> Result<Value, SqlHandlerError> {
        match self.conn.execute(DELETE_QUERY, [params.content_id]) {
            Ok(_) => Ok(Value::Null),
            Err(_) => Err(SqlHandlerError::FailedExecution {
                request_type: "Remove".to_string(),
            }),
        }
    }

    /// Insert a ContentID & its metadata into the metadata (sqlite) database
    fn insert(&self, params: InsertParams) -> Result<Value, SqlHandlerError> {
        let insert_params = params![
            params.content_id,
            params.content_id_as_u32,
            params.content_key,
            params.value_size
        ];
        match self.conn.execute(INSERT_QUERY, insert_params) {
            Ok(_val) => Ok(Value::Null),
            Err(_) => Err(SqlHandlerError::FailedExecution {
                request_type: "Insert".to_string(),
            }),
        }
    }

    /// Get the total amount of requestable data being stored in metadata (sqlite) database
    fn total_storage(&self) -> Result<Value, SqlHandlerError> {
        let mut query = match self.conn.prepare(TOTAL_DATA_SIZE_QUERY) {
            Ok(val) => val,
            Err(_) => {
                return Err(SqlHandlerError::FailedPrepare {
                    request_type: "Total Storage".to_string(),
                })
            }
        };
        let result = query.query_map([], |row| Ok(DataSizeSum { sum: row.get(0)? }));
        let sum = match result?.next() {
            Some(val) => val,
            None => {
                return Err(SqlHandlerError::FailedExecution {
                    request_type: "Total Storage".to_string(),
                });
            }
        }?
        .sum;
        Ok(json!(sum))
    }

    /// Find the farthest ContentID from the provided NodeID
    fn find_farthest(&self, params: FindFarthestParams) -> Result<Value, SqlHandlerError> {
        let node_id_u32 = PortalStorage::byte_vector_to_u32(params.node_id);
        let mut query = self.conn.prepare(XOR_FIND_FARTHEST_QUERY).unwrap();
        let mut result = query.query_map([node_id_u32], |row| {
            Ok(ContentId {
                id_long: row.get(0)?,
            })
        })?;
        let result = match result.next() {
            Some(row) => row?,
            None => return Ok(json!(null)),
        };
        let result = hex::encode(result.id_long);
        Ok(json!(result))
    }
}

// SQLite Statements
pub const CREATE_QUERY: &str = "create table if not exists content_metadata (
                                content_id_long TEXT PRIMARY KEY,
                                content_id_short INTEGER NOT NULL,
                                content_key TEXT NOT NULL,
                                content_size INTEGER
                            )";

pub const INSERT_QUERY: &str =
    "INSERT OR IGNORE INTO content_metadata (content_id_long, content_id_short, content_key, content_size)
                            VALUES (?1, ?2, ?3, ?4)";

pub const DELETE_QUERY: &str = "DELETE FROM content_metadata
                            WHERE content_id_long = (?1)";

pub const XOR_FIND_FARTHEST_QUERY: &str = "SELECT
                                    content_id_long
                                    FROM content_metadata
                                    ORDER BY ((?1 | content_id_short) - (?1 & content_id_short)) DESC";

pub const TOTAL_DATA_SIZE_QUERY: &str = "SELECT SUM(content_size) FROM content_metadata";

// SQLite Result Containers
struct ContentId {
    id_long: Vec<u8>,
}

struct DataSizeSum {
    sum: u64,
}
