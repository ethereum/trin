use std::fmt;

use serde::{Deserialize, Serialize};

/// Enum for different "core" networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Angelfood, // aka testnet
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Network::Mainnet => write!(f, "mainnet"),
            Network::Angelfood => write!(f, "angelfood"),
        }
    }
}

impl std::str::FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mainnet" => Ok(Network::Mainnet),
            "angelfood" => Ok(Network::Angelfood),
            _ => Err(format!("Unknown network: {s}")),
        }
    }
}

/// Enum for various different portal subnetworks in a "core" network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum Subnetwork {
    Beacon,
    History,
    State,
    CanonicalIndices,
    VerkleState,
    TransactionGossip,
    Utp,
}

// Pretty printed version of the subnetwork enum, used in metrics labels.
impl fmt::Display for Subnetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Subnetwork::Beacon => write!(f, "Beacon"),
            Subnetwork::History => write!(f, "History"),
            Subnetwork::State => write!(f, "State"),
            Subnetwork::CanonicalIndices => write!(f, "Canonical Indices"),
            Subnetwork::VerkleState => write!(f, "Verkle State"),
            Subnetwork::TransactionGossip => write!(f, "Transaction Gossip"),
            Subnetwork::Utp => write!(f, "uTP"),
        }
    }
}

impl std::str::FromStr for Subnetwork {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "beacon" => Ok(Subnetwork::Beacon),
            "history" => Ok(Subnetwork::History),
            "state" => Ok(Subnetwork::State),
            "canonical_indices" => Ok(Subnetwork::CanonicalIndices),
            "verkle_state" => Ok(Subnetwork::VerkleState),
            "transaction_gossip" => Ok(Subnetwork::TransactionGossip),
            "utp" => Ok(Subnetwork::Utp),
            _ => Err(format!("Unknown subnetwork: {s}")),
        }
    }
}

// Convert camel_case cli args to/from the Subnetwork enum.
impl Subnetwork {
    pub fn to_cli_arg(&self) -> String {
        match self {
            Subnetwork::Beacon => "beacon".to_string(),
            Subnetwork::History => "history".to_string(),
            Subnetwork::State => "state".to_string(),
            Subnetwork::CanonicalIndices => "canonical_indices".to_string(),
            Subnetwork::VerkleState => "verkle_state".to_string(),
            Subnetwork::TransactionGossip => "transaction_gossip".to_string(),
            Subnetwork::Utp => "utp".to_string(),
        }
    }

    /// Returns true if the subnetwork has been "fully" activated.
    pub fn is_active(&self) -> bool {
        match self {
            Subnetwork::Beacon => true,
            Subnetwork::History => true,
            Subnetwork::State => true,
            Subnetwork::CanonicalIndices => false,
            Subnetwork::VerkleState => false,
            Subnetwork::TransactionGossip => false,
            Subnetwork::Utp => false,
        }
    }
}
