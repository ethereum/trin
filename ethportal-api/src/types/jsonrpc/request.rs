use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;
use validator::{Validate, ValidationError};

use super::{
    endpoints::{BeaconEndpoint, HistoryEndpoint, StateEndpoint},
    params::Params,
};

type Responder<T, E> = mpsc::UnboundedSender<Result<T, E>>;

#[derive(Debug, Deserialize, Serialize, Validate, Clone)]
pub struct JsonRequest {
    #[validate(custom(function = "validate_jsonrpc_version"))]
    pub jsonrpc: String,
    #[serde(default = "default_params")]
    pub params: Params,
    pub method: String,
    pub id: u32,
}

impl JsonRequest {
    pub fn new(method: String, params: Params, id: u32) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            params,
            method,
            id,
        }
    }
}

impl Default for JsonRequest {
    fn default() -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            params: Params::None,
            method: "".to_string(),
            id: 0,
        }
    }
}

/// The network JSON-RPC request.
///
/// The <T> generic corresponds to the endpoint type.
#[derive(Debug, Clone)]
pub struct JsonRpcRequest<T> {
    pub endpoint: T,
    pub resp: Responder<Value, String>,
}

/// History network JSON-RPC request
pub type HistoryJsonRpcRequest = JsonRpcRequest<HistoryEndpoint>;

/// State network JSON-RPC request
pub type StateJsonRpcRequest = JsonRpcRequest<StateEndpoint>;

/// Beacon chain network JSON-RPC request
pub type BeaconJsonRpcRequest = JsonRpcRequest<BeaconEndpoint>;

fn default_params() -> Params {
    Params::None
}

fn validate_jsonrpc_version(jsonrpc: &str) -> Result<(), ValidationError> {
    if jsonrpc != "2.0" {
        return Err(ValidationError::new("Unsupported jsonrpc version"));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use validator::ValidationErrors;

    use super::*;

    #[test_log::test]
    fn test_json_validator_accepts_valid_json() {
        let request = JsonRequest {
            jsonrpc: "2.0".to_string(),
            id: 1,
            params: Params::None,
            method: "eth_blockNumber".to_string(),
        };
        assert_eq!(request.validate(), Ok(()));
    }

    #[test_log::test]
    fn test_json_validator_with_invalid_jsonrpc_field() {
        let request = JsonRequest {
            jsonrpc: "1.0".to_string(),
            id: 1,
            params: Params::None,
            method: "eth_blockNumber".to_string(),
        };
        let errors = request.validate();
        assert!(ValidationErrors::has_error(&errors, "jsonrpc"));
    }
}
