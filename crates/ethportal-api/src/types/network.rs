use std::fmt;

use alloy_chains::Chain;
use serde::{Deserialize, Serialize};

/// Enum for different "core" networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Angelfood, // aka testnet
    Sepolia,
}

impl From<Network> for Chain {
    fn from(network: Network) -> Self {
        match network {
            Network::Mainnet => Chain::mainnet(),
            Network::Angelfood => Chain::mainnet(),
            Network::Sepolia => Chain::sepolia(),
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Network::Mainnet => write!(f, "mainnet"),
            Network::Angelfood => write!(f, "angelfood"),
            Network::Sepolia => write!(f, "sepolia"),
        }
    }
}

impl std::str::FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mainnet" => Ok(Network::Mainnet),
            "angelfood" => Ok(Network::Angelfood),
            "sepolia" => Ok(Network::Sepolia),
            _ => Err(format!("Unknown network: {s}")),
        }
    }
}

/// Enum for various different portal subnetworks in a "core" network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum Subnetwork {
    Beacon,
    LegacyHistory,
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
            Subnetwork::LegacyHistory => write!(f, "Legacy History"),
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
            "legacy_history" => Ok(Subnetwork::LegacyHistory),
            "state" => Ok(Subnetwork::State),
            "canonical_indices" => Ok(Subnetwork::CanonicalIndices),
            "verkle_state" => Ok(Subnetwork::VerkleState),
            "transaction_gossip" => Ok(Subnetwork::TransactionGossip),
            "utp" => Ok(Subnetwork::Utp),
            _ => Err(format!("Unknown subnetwork: {s}")),
        }
    }
}

impl Subnetwork {
    /// Convert Subnetwork enum to camel_case cli arg.
    pub fn to_cli_arg(&self) -> String {
        match self {
            Subnetwork::Beacon => "beacon".to_string(),
            Subnetwork::LegacyHistory => "legacy_history".to_string(),
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
            Subnetwork::LegacyHistory => true,
            Subnetwork::State => true,
            Subnetwork::CanonicalIndices => false,
            Subnetwork::VerkleState => false,
            Subnetwork::TransactionGossip => false,
            Subnetwork::Utp => false,
        }
    }

    /// Returns Subnetworks that it depends on.
    pub fn dependencies(&self) -> Vec<Subnetwork> {
        match self {
            Subnetwork::LegacyHistory => vec![Subnetwork::Beacon],
            Subnetwork::State => vec![Subnetwork::LegacyHistory, Subnetwork::Beacon],
            _ => vec![],
        }
    }

    /// Returns itself and subnetworks that it depends on.
    pub fn with_dependencies(&self) -> impl IntoIterator<Item = Subnetwork> {
        Iterator::chain([*self].into_iter(), self.dependencies())
    }
}
