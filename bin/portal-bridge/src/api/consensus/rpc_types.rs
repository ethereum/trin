use alloy::primitives::{Bytes, B256};
use anyhow::bail;
use serde::Deserialize;
use serde_json::Value;
use ssz::Decode;
use ssz_derive::Decode;

#[derive(Debug, Clone, Deserialize)]
pub struct VersionedDataResponse<T> {
    pub version: Option<String>,
    pub execution_optimistic: Option<bool>,
    pub finalized: Option<bool>,
    pub data: T,
}

impl<T> VersionedDataResponse<T> {
    pub fn new(data: T, version: Option<String>) -> Self {
        Self {
            version,
            execution_optimistic: None,
            finalized: None,
            data,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum VersionedDataResult<T> {
    ExpectedResponse(VersionedDataResponse<T>),
    UnexpectedResponse(Value),
}

impl<T> VersionedDataResult<T> {
    pub fn response(self) -> anyhow::Result<VersionedDataResponse<T>> {
        match self {
            VersionedDataResult::ExpectedResponse(versioned_data_response) => {
                Ok(versioned_data_response)
            }
            VersionedDataResult::UnexpectedResponse(unexpected_response) => {
                bail!(
                    "Failed to deserialize json {}",
                    unexpected_response.to_string()
                )
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize, Decode)]
pub struct RootResponse {
    pub root: B256,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VersionResponse {
    pub version: String,
}

impl Decode for VersionResponse {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let version = Bytes::from_ssz_bytes(bytes)?;
        let version = String::from_utf8(version.to_vec()).map_err(|_| {
            ssz::DecodeError::BytesInvalid(format!("Invalid utf8 string: {version:?}"))
        })?;
        Ok(Self { version })
    }
}
