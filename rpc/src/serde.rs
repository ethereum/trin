use serde_json::{from_value as serde_json_from_value, Value};

use crate::errors::RpcServeError;

// Required for the ContentNotFound error type
#[allow(clippy::result_large_err)]
pub fn from_value<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, RpcServeError> {
    serde_json_from_value(value).map_err(|e| RpcServeError::Message(e.to_string()))
}
