use crate::ContentValueError;

pub mod beacon;
pub mod constants;
pub mod error;
pub mod history;

/// An encodable portal network content value.
pub trait ContentValue: Sized {
    /// Encodes the content value into a byte vector.
    fn encode(&self) -> Vec<u8>;
    /// Decodes `buf` into a content value.
    fn decode(buf: &[u8]) -> Result<Self, ContentValueError>;
}
