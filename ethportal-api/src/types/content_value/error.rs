use thiserror::Error;

use crate::types::network::Subnetwork;

/// An error decoding a portal network content value.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum ContentValueError {
    #[error("unable to decode value SSZ bytes {input} due to {decode_error:?}")]
    DecodeSsz {
        decode_error: ssz::DecodeError,
        input: String,
    },
    #[error("could not determine content type of {bytes} from {subnetwork:?} subnetwork")]
    UnknownContent {
        bytes: String,
        subnetwork: Subnetwork,
    },
    /// The content value is the "0x" absent content message rather than data.
    ///
    /// This error implies that handling of the "content absent" response was skipped.
    #[error("attempted to deserialize the '0x' absent content message")]
    DeserializeAbsentContent,

    /// The content value is the "0x" absent content message rather than data.
    ///
    /// This error implies that handling of the "content absent" response was skipped.
    #[error("attempted to decode the '0x' absent content message")]
    DecodeAbsentContent,
    #[error("could not determine fork digest of {bytes} from {subnetwork:?} subnetwork")]
    UnknownForkDigest {
        bytes: String,
        subnetwork: Subnetwork,
    },
    #[error("could not determine fork name of {bytes} from {subnetwork:?} subnetwork")]
    UnknownForkName {
        bytes: String,
        subnetwork: Subnetwork,
    },
}
