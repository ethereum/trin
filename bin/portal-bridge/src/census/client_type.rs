use std::fmt::Display;

use discv5::Enr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientType {
    Fluffy,
    Trin,
    Shisui,
    Ultralight,
    Samba,
    Unknown,
}

impl From<&str> for ClientType {
    fn from(value: &str) -> Self {
        let value = value.to_lowercase();
        if value.contains("fluffy") {
            ClientType::Fluffy
        } else if value.contains("trin") {
            ClientType::Trin
        } else if value.contains("shisui") {
            ClientType::Shisui
        } else if value.contains("ultralight") {
            ClientType::Ultralight
        } else if value.contains("samba") {
            ClientType::Samba
        } else {
            ClientType::Unknown
        }
    }
}

impl Display for ClientType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ClientType::Fluffy => "Fluffy",
                ClientType::Trin => "Trin",
                ClientType::Shisui => "Shisui",
                ClientType::Ultralight => "Ultralight",
                ClientType::Samba => "Samba",
                ClientType::Unknown => "Unknown",
            }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    pub enr: Enr,
    pub client_type: ClientType,
}

impl PeerInfo {
    pub fn new(enr: Enr, client_type: ClientType) -> Self {
        Self { enr, client_type }
    }
}
