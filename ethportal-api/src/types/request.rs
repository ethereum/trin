use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;
use validator::{Validate, ValidationError};

use crate::endpoints::{HistoryEndpoint, StateEndpoint, TrinEndpoint};
use trin_types::jsonrpc::params::Params;

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

// Global portal network JSON-RPC request
#[derive(Debug, Clone)]
pub struct PortalJsonRpcRequest {
    pub endpoint: TrinEndpoint,
    pub resp: Responder<Value, anyhow::Error>,
    pub params: Params,
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
