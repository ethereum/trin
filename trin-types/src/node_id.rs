use serde::{Deserialize, Serialize};
use std::ops::Deref;

type RawNodeId = [u8; 32];

/// Discv5 NodeId
// TODO: Wrap this type over discv5::NodeId type
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeId(pub RawNodeId);

impl From<RawNodeId> for NodeId {
    fn from(item: RawNodeId) -> Self {
        NodeId(item)
    }
}

impl Deref for NodeId {
    type Target = RawNodeId;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
