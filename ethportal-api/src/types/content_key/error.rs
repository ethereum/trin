use thiserror::Error;

use crate::utils::bytes::hex_encode;

/// An error decoding a portal network content key.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum ContentKeyError {
    #[error("Unable to decode key SSZ bytes {input} due to {decode_error:?}")]
    DecodeSsz {
        decode_error: ssz::DecodeError,
        input: String,
    },

    #[error("Input Vec has length {received}, expected {expected})")]
    InvalidLength { received: usize, expected: usize },
}

impl ContentKeyError {
    pub fn from_decode_error<T: AsRef<[u8]>>(decode_error: ssz::DecodeError, input: T) -> Self {
        Self::DecodeSsz {
            decode_error,
            input: hex_encode(input),
        }
    }
}
