use std::str::FromStr;

use alloy::primitives::{Bytes, B256};
use anyhow::{anyhow, bail};
use ethportal_api::{
    consensus::{beacon_state::BeaconState, fork::ForkName},
    light_client::{
        bootstrap::LightClientBootstrap, finality_update::LightClientFinalityUpdate,
        optimistic_update::LightClientOptimisticUpdate, update::LightClientUpdate,
    },
};
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

/// Trait that allows us to decode types based on provided version.
///
/// It's implemented by default for all types that implement [ssz::Decode], which simply ignores
/// the version.
pub trait VersionedDecode: Sized {
    fn decode(version: Option<&str>, bytes: &[u8]) -> anyhow::Result<Self>;
}

impl VersionedDecode for RootResponse {
    fn decode(_version: Option<&str>, bytes: &[u8]) -> anyhow::Result<Self> {
        Self::from_ssz_bytes(bytes).map_err(|err| anyhow!("Error decoding RootResponse: {err:?}"))
    }
}

impl VersionedDecode for VersionResponse {
    fn decode(_version: Option<&str>, bytes: &[u8]) -> anyhow::Result<Self> {
        let version = Bytes::from_ssz_bytes(bytes)
            .map_err(|err| anyhow!("Error decoding VersionResponse: {err:?}"))?;
        let version = String::from_utf8(version.to_vec())?;
        Ok(Self { version })
    }
}

impl VersionedDecode for LightClientBootstrap {
    fn decode(version: Option<&str>, bytes: &[u8]) -> anyhow::Result<Self> {
        let fork_name = fork_name_or_electra(version);
        Self::from_ssz_bytes(bytes, fork_name).map_err(|err| {
            anyhow!("Error decoding LightClientBootstrap (version: {version:?}), err: {err:?}")
        })
    }
}

impl VersionedDecode for LightClientUpdate {
    fn decode(version: Option<&str>, bytes: &[u8]) -> anyhow::Result<Self> {
        let fork_name = fork_name_or_electra(version);
        Self::from_ssz_bytes(bytes, fork_name).map_err(|err| {
            anyhow!("Error decoding LightClientUpdate (version: {version:?}), err: {err:?}")
        })
    }
}

impl VersionedDecode for LightClientFinalityUpdate {
    fn decode(version: Option<&str>, bytes: &[u8]) -> anyhow::Result<Self> {
        let fork_name = fork_name_or_electra(version);
        Self::from_ssz_bytes(bytes, fork_name).map_err(|err| {
            anyhow!("Error decoding LightClientFinalityUpdate (version: {version:?}), err: {err:?}")
        })
    }
}

impl VersionedDecode for LightClientOptimisticUpdate {
    fn decode(version: Option<&str>, bytes: &[u8]) -> anyhow::Result<Self> {
        let fork_name = fork_name_or_electra(version);
        Self::from_ssz_bytes(bytes, fork_name).map_err(|err| {
            anyhow!(
                "Error decoding LightClientOptimisticUpdate (version: {version:?}), err: {err:?}"
            )
        })
    }
}

impl VersionedDecode for BeaconState {
    fn decode(version: Option<&str>, bytes: &[u8]) -> anyhow::Result<Self> {
        let fork_name = fork_name_or_electra(version);
        Self::from_ssz_bytes(bytes, fork_name).map_err(|err| {
            anyhow!("Error decoding BeaconState (version: {version:?}), err: {err:?}")
        })
    }
}

fn fork_name_or_electra(version: Option<&str>) -> ForkName {
    version
        .and_then(|version| ForkName::from_str(version).ok())
        .unwrap_or(ForkName::Electra)
}
