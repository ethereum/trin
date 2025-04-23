use std::fmt::Display;

/// ClientType is not robust and should not be used for any critical logic.
/// It can't be used to reliably identify the client type from ClientInfoRadiusCapabilities, since
/// clients can include amendments to their client name, an example of this is Trin Execution uses
/// the client name "trin-execution", and hence if ClientType is used to parse this it will return
/// unknown.
///
/// For projects built on Portal like Glados, it is recommended  the respective projects maintain
/// their own client type parsing logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientType {
    Fluffy,
    Trin,
    Shisui,
    Ultralight,
    Samba,
    Unknown(Option<String>),
}

impl From<&str> for ClientType {
    fn from(value: &str) -> Self {
        let value = value.to_lowercase();
        match value.as_str() {
            "fluffy" => ClientType::Fluffy,
            "trin" => ClientType::Trin,
            "shisui" => ClientType::Shisui,
            "ultralight" => ClientType::Ultralight,
            "samba" => ClientType::Samba,
            _ => ClientType::Unknown(Some(value)),
        }
    }
}

impl Display for ClientType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientType::Unknown(Some(client)) => write!(f, "Unknown({client})"),
            ClientType::Unknown(None) => write!(f, "Unknown"),
            _ => write!(f, "{self:?}"),
        }
    }
}
