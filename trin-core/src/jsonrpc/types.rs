use ethereum_types::H256;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use ssz_types::VariableList;
use tokio::sync::mpsc;
use validator::{Validate, ValidationError};

use crate::{
    jsonrpc::{
        endpoints::{HistoryEndpoint, StateEndpoint, TrinEndpoint},
        utils::parse_content_item,
    },
    portalnet::types::{
        content_key::{OverlayContentKey, RawContentKey},
        messages::{ByteList, CustomPayload, SszEnr},
    },
    utils::bytes::hex_decode,
};

type Responder<T, E> = mpsc::UnboundedSender<Result<T, E>>;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone)]
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

        let distances: &Vec<Value> = params[1]
            .as_array()
            .ok_or_else(|| Self::Error::new("Empty distances param."))?;
        let distances: Result<Vec<u64>, Self::Error> = distances
            .iter()
            .map(|val| {
                val.as_u64()
                    .ok_or_else(|| Self::Error::new("Invalid distances param."))
            })
            .collect();
        let distances: Result<Vec<u16>, std::num::TryFromIntError> =
            distances?.into_iter().map(|val| val.try_into()).collect();
        match distances {
            Ok(val) => Ok(Self {
                enr,
                distances: val,
            }),
            Err(_) => Err(Self::Error::new("Invalid distances param.")),
        }
    }
}

#[derive(Debug)]
pub struct NodesParams {
    pub total: u8,
    pub enrs: Vec<SszEnr>,
}

impl TryFrom<&Value> for NodesParams {
    type Error = ValidationError;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let total = value
            .get("total")
            .ok_or_else(|| ValidationError::new("Missing total param"))?
            .as_u64()
            .ok_or_else(|| ValidationError::new("Invalid total param"))? as u8;

        let enrs: &Vec<Value> = value
            .get("enrs")
            .ok_or_else(|| ValidationError::new("Missing enrs param"))?
            .as_array()
            .ok_or_else(|| ValidationError::new("Empty enrs param"))?;
        let enrs: Result<Vec<SszEnr>, Self::Error> = enrs.iter().map(SszEnr::try_from).collect();

        Ok(Self { total, enrs: enrs? })
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
        let content_key = match hex_decode(content_key) {
            Ok(val) => VariableList::from(val),
            Err(_) => return Err(ValidationError::new("Unable to decode content_key")),
        };
        Ok(Self { enr, content_key })
    }
}

pub struct OfferParams<TContentKey> {
    pub content_key: TContentKey,
    pub content: Vec<u8>,
}

impl<TContentKey: OverlayContentKey> TryFrom<Params> for OfferParams<TContentKey> {
    type Error = ValidationError;

    fn try_from(params: Params) -> Result<Self, Self::Error> {
        match params {
            Params::Array(val) => match val.len() {
                2 => OfferParams::<TContentKey>::try_from([&val[0], &val[1]]),
                _ => Err(ValidationError::new("Expected 2 params")),
            },
            _ => Err(ValidationError::new("Expected array of params")),
        }
    }
}

impl<TContentKey: OverlayContentKey> TryFrom<[&Value; 2]> for OfferParams<TContentKey> {
    type Error = ValidationError;

    fn try_from(params: [&Value; 2]) -> Result<Self, Self::Error> {
        let (content_key, content) = parse_content_item(params)?;
        Ok(Self {
            content_key,
            content,
        })
    }
}

pub struct SendOfferParams {
    pub enr: SszEnr,
    pub content_keys: Vec<ByteList>,
}

impl TryFrom<Params> for SendOfferParams {
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

impl TryFrom<[&Value; 2]> for SendOfferParams {
    type Error = ValidationError;

    fn try_from(params: [&Value; 2]) -> Result<Self, Self::Error> {
        let enr: SszEnr = params[0].try_into()?;

        let content_keys = params[1].as_array();

        match content_keys {
            Some(content_keys) => {
                let content_keys: Result<Vec<String>, _> = content_keys
                    .iter()
                    .cloned()
                    .map(serde_json::from_value)
                    .collect();

                if let Ok(content_keys) = content_keys {
                    let content_keys: Result<Vec<RawContentKey>, _> = content_keys
                        .iter()
                        .map(|s| hex_decode(s.as_str()))
                        .collect();

                    if let Ok(content_keys) = content_keys {
                        Ok(Self {
                            enr,
                            content_keys: content_keys
                                .into_iter()
                                .map(VariableList::from)
                                .collect(),
                        })
                    } else {
                        Err(ValidationError::new("Unable to hex decode content keys"))
                    }
                } else {
                    Err(ValidationError::new("Unable to decode content keys"))
                }
            }
            None => Err(ValidationError::new("Required a list of content keys")),
        }
    }
}

pub struct RecursiveFindContentParams {
    pub content_key: ByteList,
}

impl TryFrom<Params> for RecursiveFindContentParams {
    type Error = ValidationError;

    fn try_from(params: Params) -> Result<Self, Self::Error> {
        match params {
            Params::Array(val) => match val.len() {
                1 => Self::try_from(&val[0]),
                _ => Err(ValidationError::new("Expected 1 param")),
            },
            _ => Err(ValidationError::new("Expected array of params")),
        }
    }
}

impl TryFrom<&Value> for RecursiveFindContentParams {
    type Error = ValidationError;

    fn try_from(param: &Value) -> Result<Self, Self::Error> {
        let content_key = param
            .as_str()
            .ok_or_else(|| ValidationError::new("Empty content key param"))?;
        let content_key = match hex_decode(content_key) {
            Ok(val) => VariableList::from(val),
            Err(_) => return Err(ValidationError::new("Unable to decode content_key")),
        };
        Ok(Self { content_key })
    }
}

pub struct GetBlockByHashParams {
    pub block_hash: [u8; 32],
    // If full_transactions is True then the 'transactions' key will
    // contain full transactions objects. Otherwise it will be an
    // array of transaction hashes.
    pub full_transactions: bool,
}

impl TryFrom<Params> for GetBlockByHashParams {
    type Error = ValidationError;

    fn try_from(params: Params) -> Result<Self, Self::Error> {
        match params {
            Params::Array(val) => match val.len() {
                2 => Self::try_from([&val[0], &val[1]]),
                _ => Err(Self::Error::new("Expected 2 params")),
            },
            _ => Err(Self::Error::new("Expected array of params")),
        }
    }
}

impl TryFrom<[&Value; 2]> for GetBlockByHashParams {
    type Error = ValidationError;

    fn try_from(params: [&Value; 2]) -> Result<Self, Self::Error> {
        let block_hash = params[0]
            .as_str()
            .ok_or_else(|| Self::Error::new("Invalid hexstring: Not a String."))?;
        let block_hash = hex_decode(block_hash)
            .map_err(|_| Self::Error::new("Invalid hexstring: Unable to decode."))?;
        let block_hash = H256::from_slice(&block_hash);
        let full_transactions = BoolParam::try_from(params[1])?;
        if full_transactions.value {
            return Err(Self::Error::new(
                "Returning full transactions with a header is not yet supported.",
            ));
        }
        Ok(Self {
            block_hash: block_hash.into(),
            full_transactions: full_transactions.value,
        })
    }
}

pub struct GetBlockByNumberParams {
    pub block_number: u64,
    // If full_transactions is True then the 'transactions' key will
    // contain full transactions objects. Otherwise it will be an
    // array of transaction hashes.
    pub full_transactions: bool,
}

impl TryFrom<Params> for GetBlockByNumberParams {
    type Error = ValidationError;

    fn try_from(params: Params) -> Result<Self, Self::Error> {
        match params {
            Params::Array(val) => match val.len() {
                2 => Self::try_from([&val[0], &val[1]]),
                _ => Err(Self::Error::new("Expected 2 params")),
            },
            _ => Err(Self::Error::new("Expected array of params")),
        }
    }
}

impl TryFrom<[&Value; 2]> for GetBlockByNumberParams {
    type Error = ValidationError;

    fn try_from(params: [&Value; 2]) -> Result<Self, Self::Error> {
        let block_number_param: String = match params[0].as_str() {
            Some(val) => val.to_string(),
            None => return Err(Self::Error::new("Invalid hexstring: Not a String.")),
        };
        let block_number = match block_number_param.strip_prefix("0x") {
            Some(val) => u64::from_str_radix(val, 16).unwrap(),
            None => match block_number_param.as_str() {
                "latest" => return Err(Self::Error::new("'latest' arg is not yet supported.")),
                "pending" => return Err(Self::Error::new("'pending' arg is not yet supported.")),
                "earliest" => 0,
                _ => return Err(Self::Error::new("Invalid block number arg.")),
            },
        };
        let full_transactions = BoolParam::try_from(params[1])?;
        if full_transactions.value {
            return Err(Self::Error::new(
                "Returning full transactions with a header is not yet supported.",
            ));
        }
        Ok(Self {
            block_number,
            full_transactions: full_transactions.value,
        })
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

    fn try_from(param: &Value) -> Result<Self, Self::Error> {
        let content_key = param
            .as_str()
            .ok_or_else(|| ValidationError::new("Empty content key param"))?;
        let content_key = match hex_decode(content_key) {
            Ok(val) => match TContentKey::try_from(val) {
                Ok(val) => val,
                Err(_) => return Err(ValidationError::new("Unable to decode content_key")),
            },
            Err(_) => return Err(ValidationError::new("Unable to decode content_key")),
        };
        Ok(Self { content_key })
    }
}

pub struct StoreParams<TContentKey> {
    pub content_key: TContentKey,
    pub content: Vec<u8>,
}

impl<TContentKey: OverlayContentKey> TryFrom<Params> for StoreParams<TContentKey> {
    type Error = ValidationError;

    fn try_from(params: Params) -> Result<Self, Self::Error> {
        match params {
            Params::Array(val) => match val.len() {
                2 => StoreParams::<TContentKey>::try_from([&val[0], &val[1]]),
                _ => Err(ValidationError::new("Expected 2 params")),
            },
            _ => Err(ValidationError::new("Expected array of params")),
        }
    }
}

impl<TContentKey: OverlayContentKey> TryFrom<[&Value; 2]> for StoreParams<TContentKey> {
    type Error = ValidationError;

    fn try_from(params: [&Value; 2]) -> Result<Self, Self::Error> {
        let (content_key, content) = parse_content_item(params)?;
        Ok(Self {
            content_key,
            content,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;
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
    #[case("[\"abc\",[0,256]]", 
        Params::Array(vec![
            Value::String("abc".to_string()),
            Value::Array(vec![
                Value::from(0),
                Value::from(256)
            ]),
        ])
    )]
    #[case("[[\"abc\", \"xyz\"],[256]]", 
        Params::Array(vec![
            Value::Array(vec![
                Value::String("abc".to_string()),
                Value::String("xyz".to_string())
            ]),
            Value::Array(vec![
                Value::from(256)
            ]),
        ])
    )]
    fn request_params_deserialization(#[case] input: &str, #[case] expected: Params) {
        let deserialized: Params = serde_json::from_str(input).unwrap();
        assert_eq!(deserialized, expected);
    }
}
