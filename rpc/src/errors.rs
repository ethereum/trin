use crate::{
    jsonrpsee::{
        core::Error as JsonRpseeError,
        types::{ErrorObject, ErrorObjectOwned},
    },
    rpc_server::ServerKind,
    PortalRpcModule,
};
use ethportal_api::types::query_trace::QueryTrace;
use std::io;

/// Rpc Errors.
#[derive(Debug, thiserror::Error)]
#[allow(clippy::enum_variant_names)]
pub enum RpcError {
    /// Wrapper for `jsonrpsee::core::Error`.
    #[error(transparent)]
    RpcError(#[from] JsonRpseeError),
    /// Address already in use.
    #[error("Address {kind} is already in use (os error 98)")]
    AddressAlreadyInUse {
        /// Server kind.
        kind: ServerKind,
        /// IO error.
        error: io::Error,
    },
    /// Http and WS server configured on the same port but with conflicting settings.
    #[error(transparent)]
    WsHttpSamePortError(#[from] WsHttpSamePortError),
    /// Custom error.
    #[error("{0}")]
    Custom(String),
}

impl RpcError {
    /// Converts a `jsonrpsee::core::Error` to a more descriptive `RpcError`.
    pub fn from_jsonrpsee_error(err: JsonRpseeError, kind: ServerKind) -> RpcError {
        match err {
            JsonRpseeError::Transport(err) => {
                if let Some(io_error) = err.downcast_ref::<io::Error>() {
                    if io_error.kind() == io::ErrorKind::AddrInUse {
                        return RpcError::AddressAlreadyInUse {
                            kind,
                            error: io::Error::from(io_error.kind()),
                        };
                    }
                }
                RpcError::RpcError(JsonRpseeError::Transport(err))
            }
            _ => err.into(),
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub enum RpcServeError {
    /// A generic error with no data
    Message(String),
    /// Method not available
    MethodNotFound(String),
    /// ContentNotFound
    ContentNotFound {
        message: String,
        trace: Option<QueryTrace>,
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
