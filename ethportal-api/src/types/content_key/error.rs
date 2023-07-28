use thiserror::Error;

/// An error decoding a portal network content key.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum ContentKeyError {
    #[error("unable to decode key SSZ bytes {input} due to {decode_error:?}")]
    DecodeSsz {
        decode_error: ssz::DecodeError,
        input: String,
    },

    #[error("Input Vec has length {received}, expected {expected})")]
    InvalidLength { received: usize, expected: usize },
}
