use ethportal_api::types::ping_extensions::extension_types::Extensions;
use portalnet::overlay::ping_extensions::PingExtension;

pub struct StatePingExtensions {}

impl StatePingExtensions {
    pub const SUPPORT_EXTENSIONS: &[Extensions] = &[
        Extensions::Capabilities,
        Extensions::BasicRadius,
        Extensions::Error,
    ];

    /// Base extensions that are required for the core subnetwork to function.
    /// These must be sorted by latest to oldest
    pub const BASE_EXTENSIONS: &[Extensions] = &[Extensions::BasicRadius];
}

impl PingExtension for StatePingExtensions {
    fn is_supported(&self, extension: Extensions) -> bool {
        Self::SUPPORT_EXTENSIONS.contains(&extension)
    }

    fn latest_mutually_supported_base_extension(
        &self,
        extensions: &[Extensions],
    ) -> Option<Extensions> {
        for base_extension in Self::BASE_EXTENSIONS {
            if extensions.contains(base_extension) {
                return Some(*base_extension);
            }
        }
        None
    }

    fn raw_extensions(&self) -> Vec<u16> {
        Self::SUPPORT_EXTENSIONS
            .iter()
            .map(|e| u16::from(*e))
            .collect()
    }
}
