use alloy::primitives::B256;
use anyhow::bail;
use serde::Deserialize;
use serde_json::Value;
use ssz_derive::Decode;

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum VersionedDataResult<T> {
    Result {
        version: Option<String>,
        execution_optimistic: Option<bool>,
        finalized: Option<bool>,
        data: T,
    },
    Error(Value),
}

impl<T> VersionedDataResult<T> {
    pub fn to_result(self) -> anyhow::Result<VersionedDataResponse<T>> {
        match self {
            VersionedDataResult::Result {
                version,
                execution_optimistic,
                finalized,
                data,
            } => Ok(VersionedDataResponse {
                version,
                execution_optimistic,
                finalized,
                data,
            }),
            VersionedDataResult::Error(err) => bail!("Failed to deserialize json {err:?}"),
        }
    }
}

#[derive(Debug, Deserialize, Decode)]
pub struct RootResponse {
    pub root: B256,
}
