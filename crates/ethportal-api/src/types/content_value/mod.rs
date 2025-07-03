use crate::{
    utils::bytes::{hex_decode, hex_encode},
    ContentValueError, OverlayContentKey, RawContentValue,
};

pub mod beacon;
pub mod constants;
pub mod error;
pub mod legacy_history;
pub mod state;

/// An encodable portal network content value.
pub trait ContentValue: Sized {
    /// The content key type associated with this content value.
    type TContentKey: OverlayContentKey;

    /// Encodes the content value into a byte vector.
    ///
    /// The [RawContentValue] is better suited than `Vec<u8>` for representing content value bytes.
    /// For more details, see [RawContentValue] documentation. If `Vec<u8>` is still desired, one
    /// can obtain it with: `value.to_bytes().to_vec()`.
    fn encode(&self) -> RawContentValue;

    /// Decodes `buf` into a content value.
    fn decode(key: &Self::TContentKey, buf: &[u8]) -> Result<Self, ContentValueError>;

    /// Encodes the content as "0x"-prefixed hex string.
    fn to_hex(&self) -> String {
        hex_encode(self.encode())
    }

    /// Decodes the "0x"-prefixed hex string as a content value.
    fn from_hex(key: &Self::TContentKey, data: &str) -> anyhow::Result<Self> {
        Ok(Self::decode(key, &hex_decode(data)?)?)
    }
}
