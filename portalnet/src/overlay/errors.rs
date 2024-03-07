use thiserror::Error;

use ethportal_api::types::query_trace::QueryTrace;

/// An overlay request error.
#[derive(Clone, Error, Debug)]
// required for the ContentNotFound error response
#[allow(clippy::large_enum_variant)]
pub enum OverlayRequestError {
    /// A failure to transmit or receive a message on a channel.
    #[error("Channel failure: {0}")]
    ChannelFailure(String),

    /// An invalid request was received.
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// An invalid response was received.
    #[error("Invalid response")]
    InvalidResponse,

    /// Received content failed validation for a response.
    #[error("Response content failed validation: {0}")]
    FailedValidation(String),

    #[error("The request returned an empty response")]
    EmptyResponse,

    /// A failure to decode a message.
    #[error("The message was unable to be decoded")]
    DecodeError,

    /// The request timed out.
    #[error("The request timed out")]
    Timeout,

    /// The request was unable to be served.
    #[error("Failure to serve request: {0}")]
    Failure(String),

    /// The request  Discovery v5 request error.
    #[error("Internal Discovery v5 error: {0}")]
    Discv5Error(discv5::RequestError),

    /// Error types resulting from building ACCEPT message
    #[error("Error while building accept message: {0}")]
    AcceptError(String),

    /// Error types resulting from building ACCEPT message
    #[error("Error while sending offer message: {0}")]
    OfferError(String),

    /// uTP request error
    #[error("uTP request error: {0}")]
    UtpError(String),

    #[error("Received invalid remote discv5 packet")]
    InvalidRemoteDiscv5Packet,

    #[error("Content wasn't found on the network: {message}")]
    ContentNotFound {
        message: String,
        utp: bool,
        trace: Option<QueryTrace>,
    },
}

impl From<discv5::RequestError> for OverlayRequestError {
    fn from(err: discv5::RequestError) -> Self {
        match err {
            discv5::RequestError::Timeout => Self::Timeout,
            discv5::RequestError::InvalidRemotePacket => Self::InvalidRemoteDiscv5Packet,
            err => Self::Discv5Error(err),
        }
    }
}
