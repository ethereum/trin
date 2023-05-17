use crate::jsonrpsee::core::Error as JsonRpseeError;
use crate::rpc_server::ServerKind;
use crate::PortalRpcModule;
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
