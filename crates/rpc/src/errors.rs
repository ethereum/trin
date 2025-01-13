use std::io;

use ethportal_api::{types::query_trace::QueryTrace, ContentValueError};
use reth_ipc::server::IpcServerStartError;
use serde::{Deserialize, Serialize};

use crate::{
    jsonrpsee::{
        server::AlreadyStoppedError,
        types::{ErrorObject, ErrorObjectOwned},
    },
    rpc_server::ServerKind,
    PortalRpcModule,
};

/// Rpc Errors.
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    /// More descriptive io::Error.
    #[error("IO Error: {0} for server kind: {1}")]
    IoError(io::Error, ServerKind),
    /// Http and WS server configured on the same port but with conflicting settings.
    #[error(transparent)]
    WsHttpSamePortError(#[from] WsHttpSamePortError),
    /// Error while starting ipc server.
    #[error(transparent)]
    IpcServerStartError(#[from] IpcServerStartError),
    /// Server already stopped.
    #[error(transparent)]
    AlreadyStoppedError(#[from] AlreadyStoppedError),
    /// Custom error.
    #[error("{0}")]
    Custom(String),
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RpcServeError {
    /// A generic error with no data
    #[error("Error: {0}")]
    Message(String),
    /// Method not available
    #[error("Method not available: {0}")]
    MethodNotFound(String),
    /// ContentNotFound
    #[error("Content not found: {message}")]
    ContentNotFound {
        message: String,
        trace: Option<Box<QueryTrace>>,
    },
}

impl From<RpcServeError> for ErrorObjectOwned {
    fn from(e: RpcServeError) -> Self {
        match e {
            // -32099 is a custom error code for a server error
            // see: https://www.jsonrpc.org/specification#error_object
            // It's a bit of a cop-out, until we implement more specific errors, being
            // sure not to conflict with the standard Ethereum error codes:
            // https://docs.infura.io/networks/ethereum/json-rpc-methods#error-codes
            RpcServeError::Message(msg) => ErrorObject::owned(-32099, msg, None::<()>),
            RpcServeError::MethodNotFound(method) => ErrorObject::owned(-32601, method, None::<()>),
            RpcServeError::ContentNotFound { message, trace } => {
                ErrorObject::owned(-39001, message, Some(trace))
            }
        }
    }
}

/// The JSON format of the "ContentNotFound" error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentNotFoundJsonError {
    pub message: String,
    pub trace: Option<QueryTrace>,
}

impl From<ContentNotFoundJsonError> for RpcServeError {
    fn from(e: ContentNotFoundJsonError) -> Self {
        RpcServeError::ContentNotFound {
            message: e.message,
            trace: e.trace.map(Box::new),
        }
    }
}

impl From<ContentValueError> for RpcServeError {
    fn from(err: ContentValueError) -> Self {
        RpcServeError::Message(format!("Error decoding content value: {err}"))
    }
}

/// Errors when trying to launch ws and http server on the same port.
#[derive(Debug, thiserror::Error)]
pub enum WsHttpSamePortError {
    /// Ws and http server configured on same port but with different cors domains.
    #[error("CORS domains for http and ws are different, but they are on the same port: http: {http_cors_domains:?}, ws: {ws_cors_domains:?}")]
    ConflictingCorsDomains {
        /// Http cors domains.
        http_cors_domains: Option<String>,
        /// Ws cors domains.
        ws_cors_domains: Option<String>,
    },
    /// Ws and http server configured on same port but with different modules.
    #[error("Different api modules for http and ws on the same port is currently not supported: http: {http_modules:?}, ws: {ws_modules:?}")]
    ConflictingModules {
        /// Http modules.
        http_modules: Vec<PortalRpcModule>,
        /// Ws modules.
        ws_modules: Vec<PortalRpcModule>,
    },
}
