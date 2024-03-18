use std::{fmt, hash::Hash, ops::Deref};

use quickcheck::{Arbitrary, Gen};

use crate::{
    types::content_key::error::ContentKeyError,
    utils::bytes::{hex_decode, hex_encode, hex_encode_compact},
};

/// Types whose values represent keys to lookup content items in an overlay network.
/// Keys are serializable.
pub trait OverlayContentKey:
    Into<Vec<u8>>
    + TryFrom<Vec<u8>, Error = ContentKeyError>
    + Clone
    + fmt::Debug
    + fmt::Display
    + Eq
    + PartialEq
    + Hash
    + std::marker::Unpin
{
    /// Returns the identifier for the content referred to by the key.
    /// The identifier locates the content in the overlay.
    fn content_id(&self) -> [u8; 32];

    /// Returns the bytes of the content key.
    fn to_bytes(&self) -> Vec<u8>;

    /// Returns the content key as a hex encoded "0x"-prefixed string.
    fn to_hex(&self) -> String {
        hex_encode(self.to_bytes())
    }

    /// Returns the content key from a hex encoded "0x"-prefixed string.
    fn from_hex(data: &str) -> anyhow::Result<Self> {
        let bytes = hex_decode(&data.to_lowercase())?;
        Ok(Self::try_from(bytes)?)
    }
}

/// A content key type whose content id is the inner value. Allows for the construction
/// of a content key with an arbitrary content ID.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IdentityContentKey {
    value: [u8; 32],
}

impl IdentityContentKey {
    /// Constructs a new `IdentityContentKey` with the specified value.
    pub fn new(value: [u8; 32]) -> Self {
        Self { value }
    }

    pub fn random() -> Self {
        Self::new(rand::random())
    }
}

impl Arbitrary for IdentityContentKey {
    fn arbitrary(g: &mut Gen) -> Self {
        let mut value = [0; 32];
        for byte in value.iter_mut() {
            *byte = u8::arbitrary(g);
        }
        Self::new(value)
    }
}

impl TryFrom<Vec<u8>> for IdentityContentKey {
    type Error = ContentKeyError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        // Require that length of input is equal to 32.
        if value.len() != 32 {
            return Err(ContentKeyError::InvalidLength {
                received: value.len(),
                expected: 32,
            });
        }

        // The following will not panic because of the length check above.
        let mut key_value: [u8; 32] = [0; 32];
        key_value.copy_from_slice(&value[..32]);

        Ok(Self { value: key_value })
    }
}

impl fmt::Display for IdentityContentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Identity {{ value: {} }}",
            hex_encode_compact(self.value)
        )
    }
}

#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for IdentityContentKey {
    fn into(self) -> Vec<u8> {
        self.value.into()
    }
}

impl Deref for IdentityContentKey {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl OverlayContentKey for IdentityContentKey {
    fn content_id(&self) -> [u8; 32] {
        self.value
    }
    fn to_bytes(&self) -> Vec<u8> {
        self.value.to_vec()
    }
}
