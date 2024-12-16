use ethportal_api::types::ping_extensions::Extensions;

pub trait PingExtension {
    fn is_supported(&self, extension: Extensions) -> bool;

    /// Returns the newest extension that is supported by both clients, used for extended ping
    /// responses.
    fn newest_commonly_supported_base_extension(
        &self,
        extensions: &[Extensions],
    ) -> Option<Extensions>;

    fn raw_extensions(&self) -> Vec<u16>;
}

pub struct MockPingExtension {}

impl PingExtension for MockPingExtension {
    fn is_supported(&self, _extension: Extensions) -> bool {
        true
    }

    fn newest_commonly_supported_base_extension(
        &self,
        _extensions: &[Extensions],
    ) -> Option<Extensions> {
        Some(Extensions::HistoryRadius)
    }

    fn raw_extensions(&self) -> Vec<u16> {
        vec![0, 1]
    }
}
