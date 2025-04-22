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
