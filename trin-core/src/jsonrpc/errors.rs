use thiserror::Error;

#[derive(Error, Debug)]
pub enum HttpParseError {
    #[error("Unable to parse http request: {0}")]
    InvalidRequest(String),
}

#[derive(Error, Debug)]
pub enum JsonRpcError {
    #[error("Invalid JsonRPC request: {0}")]
    InvalidRequest(String),

    #[error("Overlay network unavailable: {0}")]
    UnavailableNetwork(String),
}
