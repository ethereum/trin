use core::fmt;
use std::{
    fmt::{Display, Formatter},
    io,
};

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
    /// PingPayloadTypeNotSupported
    /// The client or subnetwork doesn't support this payload type.
    #[error("Ping payload type not supported: {message}")]
    PingPayloadTypeNotSupported {
        message: String,
        reason: PingPayloadTypeNotSupportedReason,
    },
    /// FailedToDecodePingPayload
    /// Failed to decode the ping payload from the payload type.
    #[error("Failed to decode ping payload: {message}")]
    FailedToDecodePingPayload { message: String },
    /// PingPayloadTypeRequired
    /// The payload type is required if the payload is specified.
    #[error("Ping payload type required: {message}")]
    PingPayloadTypeRequired { message: String },
}

impl From<RpcServeError> for ErrorObjectOwned {
    fn from(err: RpcServeError) -> Self {
        match err {
            RpcServeError::Message(message) => ErrorObject::owned(-32099, message, None::<()>),
            RpcServeError::MethodNotFound(method) => ErrorObject::owned(-32601, method, None::<()>),
            RpcServeError::ContentNotFound { message, trace } => {
                ErrorObject::owned(-39001, message, Some(trace))
            }
            RpcServeError::PingPayloadTypeNotSupported { message, reason } => {
                ErrorObject::owned(-39004, message, Some(reason.to_string()))
            }
            RpcServeError::FailedToDecodePingPayload { message } => {
                ErrorObject::owned(-39005, message, None::<()>)
            }
            RpcServeError::PingPayloadTypeRequired { message } => {
                ErrorObject::owned(-39006, message, None::<()>)
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PingPayloadTypeNotSupportedReason {
    /// The client doesn't support this payload type.
    Client,
    /// The subnetwork doesn't support this payload type.
    Subnetwork,
}

impl Display for PingPayloadTypeNotSupportedReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            PingPayloadTypeNotSupportedReason::Client => write!(f, "client"),
            PingPayloadTypeNotSupportedReason::Subnetwork => write!(f, "subnetwork"),
        }
    }
}
