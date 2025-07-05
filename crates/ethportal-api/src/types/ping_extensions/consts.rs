use super::extension_types::PingExtensionType;

pub const HISTORY_SUPPORTED_EXTENSIONS: &[PingExtensionType] = &[
    PingExtensionType::Capabilities,
    PingExtensionType::BasicRadius,
    PingExtensionType::Error,
];

pub const BEACON_SUPPORTED_EXTENSIONS: &[PingExtensionType] = &[
    PingExtensionType::Capabilities,
    PingExtensionType::BasicRadius,
    PingExtensionType::Error,
];
pub const LEGACY_HISTORY_SUPPORTED_EXTENSIONS: &[PingExtensionType] = &[
    PingExtensionType::Capabilities,
    PingExtensionType::HistoryRadius,
    PingExtensionType::Error,
];
pub const STATE_SUPPORTED_EXTENSIONS: &[PingExtensionType] = &[
    PingExtensionType::Capabilities,
    PingExtensionType::BasicRadius,
    PingExtensionType::Error,
];
