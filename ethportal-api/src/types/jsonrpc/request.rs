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
    #[validate(custom = "validate_jsonrpc_version")]
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

/// History network JSON-RPC request
#[derive(Debug, Clone)]
pub struct HistoryJsonRpcRequest {
    pub endpoint: HistoryEndpoint,
    pub resp: Responder<Value, String>,
}

/// State network JSON-RPC request
#[derive(Debug)]
pub struct StateJsonRpcRequest {
    pub endpoint: StateEndpoint,
    pub resp: Responder<Value, String>,
}

/// Beacon chain network JSON-RPC request
#[derive(Debug)]
pub struct BeaconJsonRpcRequest {
    pub endpoint: BeaconEndpoint,
    pub resp: Responder<Value, String>,
}

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
    use super::*;
    use validator::ValidationErrors;

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
