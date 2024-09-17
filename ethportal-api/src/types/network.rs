use std::fmt;

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

impl From<Subnetwork> for String {
    fn from(subnetwork: Subnetwork) -> String {
        match subnetwork {
            Subnetwork::Beacon => "beacon".to_string(),
            Subnetwork::History => "history".to_string(),
            Subnetwork::State => "state".to_string(),
        }
    }
}

impl TryFrom<&str> for Subnetwork {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "beacon" => Ok(Subnetwork::Beacon),
            "history" => Ok(Subnetwork::History),
            "state" => Ok(Subnetwork::State),
            _ => Err(format!("Unknown subnetwork: {value}")),
        }
    }
}
