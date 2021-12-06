use std::str::FromStr;

use hex::decode;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use ssz_types::VariableList;
use tokio::sync::mpsc;
use validator::{Validate, ValidationError};

use crate::jsonrpc::endpoints::{HistoryEndpoint, StateEndpoint, TrinEndpoint};
use crate::portalnet::Enr;
use crate::portalnet::types::messages::ByteList;

type Responder<T, E> = mpsc::UnboundedSender<Result<T, E>>;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(untagged)]
pub enum Params {
    /// No parameters
    None,
    /// Array of values
    Array(Vec<Value>),
    /// Map of values
    Map(Map<String, Value>),
}

impl From<Params> for Value {
    fn from(params: Params) -> Value {
        match params {
            Params::Array(vec) => Value::Array(vec),
            Params::Map(map) => Value::Object(map),
            Params::None => Value::Null,
        }
    }
}

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
    pub resp: Responder<Value, String>,
    pub params: Params,
}

/// History network JSON-RPC request
#[derive(Debug)]
pub struct HistoryJsonRpcRequest {
    pub endpoint: HistoryEndpoint,
    pub resp: Responder<Value, String>,
    pub params: Params,
}

/// State network JSON-RPC request
#[derive(Debug)]
pub struct StateJsonRpcRequest {
    pub endpoint: StateEndpoint,
    pub resp: Responder<Value, String>,
    pub params: Params,
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

pub struct PingParams {
    pub enr: Enr,
}

impl TryFrom<Params> for PingParams {
    type Error = ValidationError;

    fn try_from(params: Params) -> Result<Self, Self::Error> {
        match params {
            Params::Array(val) => match val.len() {
                1 => PingParams::try_from(&val[0]),
                _ => Err(ValidationError::new("Expected only a single param")),
            },
            _ => Err(ValidationError::new("Expected array of params")),
        }
    }
}

impl TryFrom<&Value> for PingParams {
    type Error = ValidationError;

    fn try_from(param: &Value) -> Result<Self, Self::Error> {
        match param.as_str() {
            Some(val) => match Enr::from_str(val) {
                Ok(enr) => Ok(Self { enr }),
                Err(_) => Err(ValidationError::new("Invalid enr param")),
            },
            None => Err(ValidationError::new("Missing or empty enr param")),
        }
    }
}
    
pub struct FindContentParams {
    pub enr: Enr,
    pub content_key: ByteList,
}

impl TryFrom<Params> for FindContentParams {
    type Error = ValidationError;

    fn try_from(params: Params) -> Result<Self, Self::Error> {
        println!("params innit: {:?}", params);
        match params {
           Params::Array(val) => match val.len() {
                2 => FindContentParams::try_from(&val),
                _ => Err(ValidationError::new("Expected 2 params")),
            },
            _ => Err(ValidationError::new("Expected array of params")),
        }
    }
}

impl TryFrom<&Vec<Value>> for FindContentParams {
    type Error = ValidationError;

    fn try_from(params: &Vec<Value>) -> Result<Self, Self::Error> {
        // handle unwrap()(s)
        let raw = params[0].as_str().unwrap();
        let enr = match Enr::from_str(raw) {
            Ok(enr) => enr,
            Err(_msg) => {
                return Err(ValidationError::new("Invalid enr param"))
            }
        };
        let content_key = match decode(params[1].as_str().unwrap()) {
            Ok(val) => ByteList::from(VariableList::from(val)),
            Err(_msg) => return Err(ValidationError::new("Unable to decode content_key")),
        };
        Ok(Self {enr, content_key} )
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;
    use validator::ValidationErrors;

    #[test]
    fn test_json_validator_accepts_valid_json() {
        let request = JsonRequest {
            jsonrpc: "2.0".to_string(),
            id: 1,
            params: Params::None,
            method: "eth_blockNumber".to_string(),
        };
        assert_eq!(request.validate(), Ok(()));
    }

    #[test]
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

    fn expected_map() -> Map<String, Value> {
        let mut expected_map = serde_json::Map::new();
        expected_map.insert("key".to_string(), Value::String("value".to_string()));
        expected_map
    }

    #[rstest]
    #[case("[null]", Params::Array(vec![Value::Null]))]
    #[case("[true]", Params::Array(vec![Value::Bool(true)]))]
    #[case("[-1]", Params::Array(vec![Value::from(-1)]))]
    #[case("[4]", Params::Array(vec![Value::from(4)]))]
    #[case("[2.3]", Params::Array(vec![Value::from(2.3)]))]
    #[case("[\"hello\"]", Params::Array(vec![Value::String("hello".to_string())]))]
    #[case("[[0]]", Params::Array(vec![Value::Array(vec![Value::from(0)])]))]
    #[case("[[]]", Params::Array(vec![Value::Array(vec![])]))]
    #[case("[{\"key\": \"value\"}]", Params::Array(vec![Value::Object(expected_map())]))]
    fn request_params_deserialization(#[case] input: &str, #[case] expected: Params) {
        let deserialized: Params = serde_json::from_str(input).unwrap();
        assert_eq!(deserialized, expected);
    }
}
