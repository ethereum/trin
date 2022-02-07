/// Types whose values represent keys to lookup content items in an overlay network.
/// Keys are serializable.
pub trait OverlayContentKey: Into<Vec<u8>> + TryFrom<Vec<u8>> + Clone {
    /// Returns the identifier for the content referred to by the key.
    /// The identifier locates the content in the overlay.
    fn content_id(&self) -> [u8; 32];
}

// Mock type for testing
#[derive(Clone)]
pub struct MockContentKey {
    value: Vec<u8>,
}

impl TryFrom<Vec<u8>> for MockContentKey {
    type Error = String;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(MockContentKey { value })
    }
}

impl Into<Vec<u8>> for MockContentKey {
    fn into(self) -> Vec<u8> {
        self.value
    }
}

impl OverlayContentKey for MockContentKey {
    fn content_id(&self) -> [u8; 32] {
        [0; 32]
    }
}
