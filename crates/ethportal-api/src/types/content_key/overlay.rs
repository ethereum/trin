use std::{fmt, hash::Hash, ops::Deref, str::FromStr};

use quickcheck::{Arbitrary, Gen};
use sha2::{Digest, Sha256};

use crate::{
    types::content_key::error::ContentKeyError,
    utils::bytes::{hex_encode, hex_encode_compact},
    RawContentKey,
};

/// Types whose values represent keys to lookup content items in an overlay network.
///
/// Keys are serializable as "0x" prefixed hex strings.
pub trait OverlayContentKey:
    Clone + fmt::Debug + fmt::Display + Eq + PartialEq + Hash + std::marker::Unpin
{
    /// Returns the identifier for the content referred to by the key.
    /// The identifier locates the content in the overlay.
    fn content_id(&self) -> [u8; 32] {
        Sha256::digest(self.to_bytes()).into()
    }

    /// Returns the bytes of the content key.
    ///
    /// The [RawContentKey] is better suited than `Vec<u8>` for representing content key bytes.
    /// For more details, see [RawContentKey] documentation. If `Vec<u8>` is still desired, one can
    /// obtain it with: `key.to_bytes().to_vec()`.
    fn to_bytes(&self) -> RawContentKey;

    /// Decodes bytes as content key.
    fn try_from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, ContentKeyError>;

    /// Returns the content key as a hex encoded "0x"-prefixed string.
    fn to_hex(&self) -> String {
        hex_encode(self.to_bytes())
    }

    /// Returns the content key from a hex encoded "0x"-prefixed string.
    fn try_from_hex(data: &str) -> anyhow::Result<Self> {
        Ok(Self::try_from_bytes(RawContentKey::from_str(data)?)?)
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
    fn to_bytes(&self) -> RawContentKey {
        RawContentKey::from(self.value)
    }

    fn try_from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, ContentKeyError> {
        // Require that length of input is equal to 32.
        let bytes = bytes.as_ref();
        if bytes.len() != 32 {
            return Err(ContentKeyError::InvalidLength {
                received: bytes.len(),
                expected: 32,
            });
        }

        // The following will not panic because of the length check above.
        let mut key_value: [u8; 32] = [0; 32];
        key_value.copy_from_slice(&bytes[..32]);

        Ok(Self { value: key_value })
    }
}
