/// Types whose values represent keys to lookup content items in an overlay network.
/// Keys are serializable.
pub trait OverlayContentKey: Into<Vec<u8>> + TryFrom<Vec<u8>> + Clone {
    /// Returns the identifier for the content referred to by the key.
    /// The identifier locates the content in the overlay.
    fn content_id(&self) -> [u8; 32];
}

/// A content key type whose content id is the inner value. Allows for the construction
/// of a content key with an arbitary content ID.
#[derive(Clone)]
pub struct IdentityContentKey {
    value: [u8; 32],
}

impl IdentityContentKey {
    /// Constructs a new `IdentityContentKey` with the specified value.
    pub fn new(value: [u8; 32]) -> Self {
        Self { value }
    }
}

impl TryFrom<Vec<u8>> for IdentityContentKey {
    type Error = String;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        // Require that length of input is equal to 32.
        if value.len() != 32 {
            return Err(String::from("Input Vec has invalid length"));
        }

        // The following will not panic because of the length check above.
        let mut key_value: [u8; 32] = [0; 32];
        key_value.copy_from_slice(&value[..32]);

        Ok(Self { value: key_value })
    }
}

impl Into<Vec<u8>> for IdentityContentKey {
    fn into(self) -> Vec<u8> {
        self.value.into()
    }
}

impl OverlayContentKey for IdentityContentKey {
    fn content_id(&self) -> [u8; 32] {
        self.value
    }
}
