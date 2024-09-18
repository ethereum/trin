use std::fmt;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subnetwork {
    Beacon,
    History,
    State,
}

impl fmt::Display for Subnetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Subnetwork::Beacon => write!(f, "beacon"),
            Subnetwork::History => write!(f, "history"),
            Subnetwork::State => write!(f, "state"),
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
            _ => Err(format!("Unknown subnetwork: {s}")),
        }
    }
}
