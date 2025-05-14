use std::{fmt::Display, str::FromStr};

use alloy::{
    primitives::{Bytes, B256},
    rpc::types::beacon::events::{
        ChainReorgEvent, FinalizedCheckpointEvent, HeadEvent, LightClientOptimisticUpdateEvent,
    },
};
use anyhow::bail;
use eventsource_client::Event;
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

/// Represents the topics for events that can be subscribed to. Not all event topics are listed in
/// this enum. More topics can be found in the documentation https://ethereum.github.io/beacon-APIs/#/Events/eventstream
pub enum EventTopics {
    ChainReorg,
    Head,
    LightClientOptimisticUpdate,
    FinalizedCheckpoint,
}

impl Display for EventTopics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventTopics::ChainReorg => write!(f, "chain_reorg"),
            EventTopics::Head => write!(f, "head"),
            EventTopics::LightClientOptimisticUpdate => {
                write!(f, "light_client_optimistic_update")
            }
            EventTopics::FinalizedCheckpoint => write!(f, "finalized_checkpoint"),
        }
    }
}

impl FromStr for EventTopics {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "chain_reorg" => Ok(EventTopics::ChainReorg),
            "head" => Ok(EventTopics::Head),
            "light_client_optimistic_update" => Ok(EventTopics::LightClientOptimisticUpdate),
            "finalized_checkpoint" => Ok(EventTopics::FinalizedCheckpoint),
            _ => bail!("Invalid event topic: {s}"),
        }
    }
}

pub enum DecodedEvent {
    ChainReorg(ChainReorgEvent),
    Head(HeadEvent),
    LightClientOptimisticUpdate(LightClientOptimisticUpdateEvent),
    FinalizedCheckpoint(FinalizedCheckpointEvent),
}

impl TryFrom<Event> for DecodedEvent {
    type Error = anyhow::Error;

    fn try_from(event: Event) -> Result<Self, Self::Error> {
        match EventTopics::from_str(&event.event_type)? {
            EventTopics::ChainReorg => {
                let chain_reorg = serde_json::from_str::<ChainReorgEvent>(&event.data)?;
                Ok(DecodedEvent::ChainReorg(chain_reorg))
            }
            EventTopics::Head => {
                let head = serde_json::from_str::<HeadEvent>(&event.data)?;
                Ok(DecodedEvent::Head(head))
            }
            EventTopics::FinalizedCheckpoint => {
                let finalized_checkpoint =
                    serde_json::from_str::<FinalizedCheckpointEvent>(&event.data)?;
                Ok(DecodedEvent::FinalizedCheckpoint(finalized_checkpoint))
            }
            EventTopics::LightClientOptimisticUpdate => {
                let light_client_optimistic_update =
                    serde_json::from_str::<LightClientOptimisticUpdateEvent>(&event.data)?;
                Ok(DecodedEvent::LightClientOptimisticUpdate(
                    light_client_optimistic_update,
                ))
            }
        }
    }
}
