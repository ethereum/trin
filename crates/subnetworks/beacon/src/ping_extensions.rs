use ethportal_api::types::ping_extensions::{
    consts::BEACON_SUPPORTED_EXTENSIONS, extension_types::PingExtensionType,
};
use portalnet::overlay::ping_extensions::PingExtensions;

pub struct BeaconPingExtensions {}

impl BeaconPingExtensions {
    pub const SUPPORTED_EXTENSIONS: &[PingExtensionType] = BEACON_SUPPORTED_EXTENSIONS;

    /// Base extensions that are required for the core subnetwork to function.
    /// These must be sorted by latest to oldest
    pub const BASE_EXTENSIONS: &[PingExtensionType] = &[PingExtensionType::BasicRadius];
}

impl PingExtensions for BeaconPingExtensions {
    fn latest_mutually_supported_base_extension(
        &self,
        extensions: &[PingExtensionType],
    ) -> Option<PingExtensionType> {
        for base_extension in Self::BASE_EXTENSIONS {
            if extensions.contains(base_extension) {
                return Some(*base_extension);
            }
        }
        None
    }

    fn supported_extensions(&self) -> &[PingExtensionType] {
        Self::SUPPORTED_EXTENSIONS
    }
}
