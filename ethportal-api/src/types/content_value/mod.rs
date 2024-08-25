use crate::{
    utils::bytes::{hex_decode, hex_encode},
    ContentValueError, OverlayContentKey, RawContentValue,
};

pub mod beacon;
pub mod constants;
pub mod error;
pub mod history;
pub mod state;

/// An encodable portal network content value.
pub trait ContentValue: Sized {
    type TContentKey: OverlayContentKey;

    /// Encodes the content value into a byte vector.
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
