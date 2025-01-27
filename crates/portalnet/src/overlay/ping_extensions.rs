use ethportal_api::types::ping_extensions::extension_types::Extensions;

pub trait PingExtension {
    /// Returns true if the extension is supported by the clients subnetwork.
    fn is_supported(&self, extension: Extensions) -> bool;

    /// Returns the newest extension that is supported by both clients, used for extended ping
    /// responses.
    fn latest_mutually_supported_base_extension(
        &self,
        extensions: &[Extensions],
    ) -> Option<Extensions>;

    /// Returns the extensions by their u16 type id that are supported by the clients subnetwork.
    fn raw_extensions(&self) -> Vec<u16>;
}

pub struct MockPingExtension {}

impl PingExtension for MockPingExtension {
    fn is_supported(&self, _extension: Extensions) -> bool {
        true
    }

    fn latest_mutually_supported_base_extension(
        &self,
        _extensions: &[Extensions],
    ) -> Option<Extensions> {
        Some(Extensions::HistoryRadius)
    }

    fn raw_extensions(&self) -> Vec<u16> {
        vec![0, 1]
    }
}
