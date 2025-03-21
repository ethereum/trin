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

impl PingExtensions for MockPingExtension {
    fn is_supported(&self, _extension: PingExtensionType) -> bool {
        true
    }

    fn latest_mutually_supported_base_extension(
        &self,
        _extensions: &[PingExtensionType],
    ) -> Option<PingExtensionType> {
        Some(PingExtensionType::HistoryRadius)
    }

    fn supported_extensions(&self) -> &[PingExtensionType] {
        &[
            PingExtensionType::Capabilities,
            PingExtensionType::BasicRadius,
        ]
    }
}
