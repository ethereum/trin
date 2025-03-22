use ethportal_api::types::ping_extensions::extension_types::PingExtensionType;

pub trait PingExtensions {
    /// Returns true if the extension is supported by the clients subnetwork.
    fn is_supported(&self, extension: PingExtensionType) -> bool {
        self.supported_extensions().contains(&extension)
    }

    /// Returns the newest extension that is supported by both clients, used for extended ping
    /// responses.
    fn latest_mutually_supported_base_extension(
        &self,
        extensions: &[PingExtensionType],
    ) -> Option<PingExtensionType>;

    /// Returns the extensions that are supported by the clients subnetwork.
    fn supported_extensions(&self) -> &[PingExtensionType];
}

pub struct MockPingExtension;

impl MockPingExtension {
    pub const SUPPORTED_EXTENSIONS: &[PingExtensionType] = &[
        PingExtensionType::Capabilities,
        PingExtensionType::BasicRadius,
    ];

    /// Base extensions that are required for the core subnetwork to function.
    /// These must be sorted by latest to oldest
    pub const BASE_EXTENSIONS: &[PingExtensionType] = &[PingExtensionType::BasicRadius];
}

impl PingExtensions for MockPingExtension {
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
