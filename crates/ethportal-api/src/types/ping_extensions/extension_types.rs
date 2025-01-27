#[derive(PartialEq, Debug, Clone, Copy, Eq)]
pub enum Extensions {
    Capabilities,
    BasicRadius,
    HistoryRadius,
    Error,
}

impl TryFrom<u16> for Extensions {
    type Error = ExtensionError;

    fn try_from(value: u16) -> Result<Self, ExtensionError> {
        match value {
            0 => Ok(Extensions::Capabilities),
            1 => Ok(Extensions::BasicRadius),
            2 => Ok(Extensions::HistoryRadius),
            65535 => Ok(Extensions::Error),
            _ => Err(ExtensionError::NonSupportedExtension(value)),
        }
    }
}

impl From<Extensions> for u16 {
    fn from(value: Extensions) -> u16 {
        match value {
            Extensions::Capabilities => 0,
            Extensions::BasicRadius => 1,
            Extensions::HistoryRadius => 2,
            Extensions::Error => 65535,
        }
    }
}

#[derive(Debug)]
pub enum ExtensionError {
    NonSupportedExtension(u16),
}
