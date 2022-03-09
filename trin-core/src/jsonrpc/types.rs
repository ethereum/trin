use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use ssz_types::VariableList;
use tokio::sync::mpsc;
use validator::{Validate, ValidationError};

use crate::jsonrpc::endpoints::{HistoryEndpoint, StateEndpoint, TrinEndpoint};
use crate::portalnet::types::content_key::OverlayContentKey;
use crate::portalnet::types::messages::{ByteList, CustomPayload, SszEnr};

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
    pub resp: Responder<Value, anyhow::Error>,
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
    pub enr: SszEnr,
    pub custom_payload: Option<CustomPayload>,
}

impl TryFrom<Params> for PingParams {
    type Error = ValidationError;

    fn try_from(params: Params) -> Result<Self, Self::Error> {
        match params {
            Params::Array(val) => match val.len() {
                1 => PingParams::try_from(&val[0]),
                2 => PingParams::try_from([&val[0], &val[1]]),
                _ => Err(ValidationError::new("Expected 1 or 2 params")),
            },
            _ => Err(ValidationError::new("Expected array of params")),
        }
    }
}

impl TryFrom<&Value> for PingParams {
    type Error = ValidationError;

    fn try_from(param: &Value) -> Result<Self, Self::Error> {
        let enr: SszEnr = param.try_into()?;
        Ok(Self {
            enr,
            custom_payload: None,
        })
    }
}

impl TryFrom<[&Value; 2]> for PingParams {
    type Error = ValidationError;

    fn try_from(param: [&Value; 2]) -> Result<Self, Self::Error> {
        let enr: SszEnr = param[0].try_into()?;
        let custom_payload: CustomPayload = param[1].try_into()?;
        Ok(Self {
            enr,
            custom_payload: Some(custom_payload),
        })
    }
}

pub struct FindNodesParams {
    pub enr: SszEnr,
    pub distances: Vec<u16>,
}

impl TryFrom<Params> for FindNodesParams {
    type Error = ValidationError;

    fn try_from(params: Params) -> Result<Self, Self::Error> {
        match params {
            Params::Array(val) => match val.len() {
                2 => FindNodesParams::try_from([&val[0], &val[1]]),
                _ => Err(ValidationError::new("Expected 2 params")),
            },
            _ => Err(ValidationError::new("Expected array of params")),
        }
    }
}

impl TryFrom<[&Value; 2]> for FindNodesParams {
    type Error = ValidationError;

    fn try_from(params: [&Value; 2]) -> Result<Self, Self::Error> {
        let enr: SszEnr = params[0].try_into()?;

        let distances = params[1]
            .as_str()
            .ok_or_else(|| ValidationError::new("Empty distances param"))?;
        let distances: Vec<u16> = match serde_json::from_str(distances) {
            Ok(val) => val,
            Err(_) => return Err(ValidationError::new("Unable to decode distances")),
        };
        Ok(Self { enr, distances })
    }
}

pub struct FindContentParams {
    pub enr: SszEnr,
    pub content_key: ByteList,
}

impl TryFrom<Params> for FindContentParams {
    type Error = ValidationError;

    fn try_from(params: Params) -> Result<Self, Self::Error> {
        match params {
            Params::Array(val) => match val.len() {
                2 => FindContentParams::try_from([&val[0], &val[1]]),
                _ => Err(ValidationError::new("Expected 2 params")),
            },
            _ => Err(ValidationError::new("Expected array of params")),
        }
    }
}

impl TryFrom<[&Value; 2]> for FindContentParams {
    type Error = ValidationError;

    fn try_from(params: [&Value; 2]) -> Result<Self, Self::Error> {
        let enr: SszEnr = params[0].try_into()?;
        let content_key = params[1]
            .as_str()
            .ok_or_else(|| ValidationError::new("Empty content key param"))?;
        let content_key = match hex::decode(content_key) {
            Ok(val) => VariableList::from(val),
            Err(_) => return Err(ValidationError::new("Unable to decode content_key")),
        };
        Ok(Self { enr, content_key })
    }
}

pub struct RecursiveFindContentParams {
    pub content_key: ByteList,
    pub hydrated_transactions: bool,
}

impl TryFrom<Params> for RecursiveFindContentParams {
    type Error = ValidationError;

    fn try_from(params: Params) -> Result<Self, Self::Error> {
        match params {
            Params::Array(val) => match val.len() {
                2 => Self::try_from([&val[0], &val[1]]),
                _ => Err(ValidationError::new("Expected 2 params")),
            },
            _ => Err(ValidationError::new("Expected array of params")),
        }
    }
}

impl TryFrom<[&Value; 2]> for RecursiveFindContentParams {
    type Error = ValidationError;

    fn try_from(params: [&Value; 2]) -> Result<Self, Self::Error> {
        let content_key = params[0]
            .as_str()
            .ok_or_else(|| ValidationError::new("Empty content key param"))?;
        let content_key = match hex::decode(content_key) {
            Ok(val) => VariableList::from(val),
            Err(_) => return Err(ValidationError::new("Unable to decode content_key")),
        };
        let hydrated_transactions: BoolParam = params[1].try_into()?;
        Ok(Self {
            content_key,
            hydrated_transactions: hydrated_transactions.value,
        })
    }
}

pub struct GetBlockByHashParams {
    pub block_hash: [u8; 32],
    pub hydrated_transactions: bool,
}

impl TryFrom<Params> for GetBlockByHashParams {
    type Error = ValidationError;

    fn try_from(params: Params) -> Result<Self, Self::Error> {
        match params {
            Params::Array(val) => match val.len() {
                2 => GetBlockByHashParams::try_from([&val[0], &val[1]]),
                _ => Err(ValidationError::new("Expected 2 params")),
            },
            _ => Err(ValidationError::new("Expected array of params")),
        }
    }
}

impl TryFrom<[&Value; 2]> for GetBlockByHashParams {
    type Error = ValidationError;

    fn try_from(params: [&Value; 2]) -> Result<Self, Self::Error> {
        let block_hash: BlockHash = params[0].try_into()?;
        let hydrated_transactions = BoolParam::try_from(params[1])?;
        Ok(Self {
            block_hash: block_hash.value,
            hydrated_transactions: hydrated_transactions.value,
        })
    }
}

pub struct BlockHash {
    pub value: [u8; 32],
}

impl TryFrom<&Value> for BlockHash {
    type Error = ValidationError;

    fn try_from(param: &Value) -> Result<Self, Self::Error> {
        let block_hash = param
            .as_str()
            .ok_or_else(|| Self::Error::new("Invalid block hash param: Expected string."))?;

        let prefix: String = block_hash.chars().skip(0).take(2).collect();
        if prefix != "0x" {
            return Err(Self::Error::new(
                "Invalid block hash: Expected 0x-prefixed hexstring",
            ));
        }
        if block_hash.len() != 66 {
            return Err(Self::Error::new(
                "Invalid block hash length: Expected 0x-prefixed 32 byte hexstring",
            ));
        }
        let prefix_removed_block_hash = &block_hash[2..block_hash.len()];
        let block_hash = match hex::decode(prefix_removed_block_hash) {
            Ok(val) => val,
            Err(_) => return Err(Self::Error::new("Unable to decode hex string")),
        };
        let mut value = [0u8; 32];
        value.copy_from_slice(block_hash.as_slice());
        Ok(Self { value })
    }
}

#[derive(Debug)]
pub struct BoolParam {
    value: bool,
}

impl TryFrom<&Value> for BoolParam {
    type Error = ValidationError;

    // Deserializes both Value::Bool and Value::String("true" || "false")
    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        match value {
            Value::Bool(val) => Ok(Self { value: *val }),
            Value::String(val) => match val.parse::<bool>() {
                Ok(val) => Ok(Self { value: val }),
                Err(_) => Err(ValidationError::new(
                    "Invalid boolean parameter: Expected 'true' or 'false'.",
                )),
            },
            _ => Err(ValidationError::new("Invalid boolean parameter")),
        }
    }
}

pub struct LocalContentParams<TContentKey> {
    pub content_key: TContentKey,
}

impl<TContentKey: OverlayContentKey> TryFrom<Params> for LocalContentParams<TContentKey> {
    type Error = ValidationError;

    fn try_from(params: Params) -> Result<Self, Self::Error> {
        match params {
            Params::Array(val) => match val.len() {
                1 => LocalContentParams::<TContentKey>::try_from(&val[0]),
                _ => Err(ValidationError::new("Expected 1 param")),
            },
            _ => Err(ValidationError::new("Expected array of params")),
        }
    }
}

impl<TContentKey: OverlayContentKey> TryFrom<&Value> for LocalContentParams<TContentKey> {
    type Error = ValidationError;

    fn try_from(params: &Value) -> Result<Self, Self::Error> {
        let content_key = params[0]
            .as_str()
            .ok_or_else(|| ValidationError::new("Empty content key param"))?;
        let content_key = match hex::decode(content_key) {
            Ok(val) => match TContentKey::try_from(val) {
                Ok(val) => val,
                Err(_) => return Err(ValidationError::new("Unable to decode content_key")),
            },
            Err(_) => return Err(ValidationError::new("Unable to decode content_key")),
        };
        Ok(Self { content_key })
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

    #[test]
    fn block_hash_valid_values() {
        BlockHash::try_from(&Value::String(
            "0x2c6c2f0b25e36b96a3dddd756f130fb0645a59a59cdf6255bba426b390c73ca7".to_string(),
        ))
        .unwrap();
    }

    #[rstest]
    #[case(Value::Bool(false))]
    #[case(Value::String("0".to_string()))]
    // No 0x prefix
    #[case(Value::String("2c6c2f0b25e36b96a3dddd756f130fb0645a59a59cdf6255bba426b390c73ca7".to_string()))]
    #[case(Value::String("x2c6c2f0b25e36b96a3dddd756f130fb0645a59a59cdf6255bba426b390c73ca7".to_string()))]
    #[case(Value::String("Ox2c6c2f0b25e36b96a3dddd756f130fb0645a59a59cdf6255bba426b390c73ca7".to_string()))]
    // Invalid Length
    #[case(Value::String("0x2c6c2f0b25e36b96a3dddd756f130fb0645a59a59cdf6255bba426b390c73c".to_string()))]
    #[case(Value::String("0x2c6c2f0b25e36b96a3dddd756f130fb0645a59a59cdf6255bba426b390c73ca700".to_string()))]
    // Not a hexstring
    #[case(Value::String("0xhhhc2f0b25e36b96a3dddd756f130fb0645a59a59cdf6255bba426b390c73ca7".to_string()))]
    #[should_panic]
    fn block_hash_catches_invalid_values(#[case] block_hash: Value) {
        BlockHash::try_from(&block_hash).unwrap();
    }
}
