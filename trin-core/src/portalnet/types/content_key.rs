pub trait OverlayContentKey: Into<Vec<u8>> + TryFrom<Vec<u8>> {
    fn content_id(&self) -> [u8; 32];
}
