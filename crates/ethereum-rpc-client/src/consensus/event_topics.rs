use std::{fmt::Display, str::FromStr};

use alloy::rpc::types::beacon::events::{
    ChainReorgEvent, FinalizedCheckpointEvent, HeadEvent, LightClientOptimisticUpdateEvent,
};
use anyhow::bail;
use eventsource_client::Event;

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
                Ok(serde_json::from_str(&event.data).map(DecodedEvent::ChainReorg)?)
            }
            EventTopics::Head => Ok(serde_json::from_str(&event.data).map(DecodedEvent::Head)?),
            EventTopics::FinalizedCheckpoint => {
                Ok(serde_json::from_str(&event.data).map(DecodedEvent::FinalizedCheckpoint)?)
            }
            EventTopics::LightClientOptimisticUpdate => {
                Ok(serde_json::from_str(&event.data)
                    .map(DecodedEvent::LightClientOptimisticUpdate)?)
            }
        }
    }
}
