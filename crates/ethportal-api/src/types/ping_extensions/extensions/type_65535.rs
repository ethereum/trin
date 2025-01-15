use ssz::Encode;
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum::U300, VariableList};

use crate::types::{
    ping_extensions::custom_payload_format::CustomPayloadExtensionsFormat,
    portal_wire::CustomPayload,
};

/// Used to respond to pings which the node can't handle
#[derive(PartialEq, Debug, Clone, Encode, Decode)]
pub struct PingError {
    pub error_code: u16,
    pub message: VariableList<u8, U300>,
}

impl PingError {
    pub fn new(error_code: ErrorCodes) -> Self {
        Self {
            error_code: error_code.into(),
            message: VariableList::empty(),
        }
    }
}

impl From<PingError> for CustomPayload {
    fn from(ping_error: PingError) -> Self {
        CustomPayload::from(
            CustomPayloadExtensionsFormat {
                r#type: 65535,
                payload: ping_error.as_ssz_bytes().into(),
            }
            .as_ssz_bytes(),
        )
    }
}

pub enum ErrorCodes {
    ExtensionNotSupported,
    RequestedDataNotFound,
    FailedToDecodePayload,
    SystemError,
}

impl From<ErrorCodes> for u16 {
    fn from(error_code: ErrorCodes) -> u16 {
        match error_code {
            ErrorCodes::ExtensionNotSupported => 0,
            ErrorCodes::RequestedDataNotFound => 1,
            ErrorCodes::FailedToDecodePayload => 2,
            ErrorCodes::SystemError => 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use ssz::Decode;

    use super::*;
    use crate::types::ping_extensions::decode::DecodedExtension;

    #[test]
    fn test_ping_error() {
        let error_code = ErrorCodes::ExtensionNotSupported;
        let ping_error = PingError::new(error_code);
        let custom_payload = CustomPayload::from(ping_error.clone());

        let decoded_extension = DecodedExtension::try_from(custom_payload).unwrap();

        if let DecodedExtension::Error(decoded_ping_error) = decoded_extension {
            assert_eq!(ping_error, decoded_ping_error);
        } else {
            panic!("Decoded extension is not PingError");
        }
    }

    #[test]
    fn test_ping_error_ssz_round_trip() {
        let error_code = ErrorCodes::ExtensionNotSupported;
        let ping_error = PingError::new(error_code);
        let bytes = ping_error.as_ssz_bytes();
        let decoded = PingError::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(bytes.len(), 6);
        assert_eq!(ping_error, decoded);
    }
}
