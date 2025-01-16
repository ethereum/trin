use anyhow::anyhow;
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

    pub fn new_with_message(error_code: ErrorCodes, message: Vec<u8>) -> anyhow::Result<Self> {
        Ok(Self {
            error_code: error_code.into(),
            message: VariableList::new(message).map_err(|err| {
                anyhow!("PingError can only handle messages up to 300 bytes, received {err:?}")
            })?,
        })
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
    use crate::{
        types::{
            ping_extensions::decode::DecodedExtension,
            portal_wire::{Message, Pong},
        },
        utils::bytes::{hex_decode, hex_encode},
    };

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

    #[rstest::rstest]
    #[case(301, true)]
    #[case(300, false)]
    fn test_ping_error_message_too_long(#[case] message_length: usize, #[case] expected: bool) {
        let error_code = ErrorCodes::FailedToDecodePayload;
        let message = vec![0; message_length];
        assert_eq!(
            PingError::new_with_message(error_code, message).is_err(),
            expected
        );
    }

    #[test]
    fn message_encoding_pong_basic_radius() {
        let error_code = ErrorCodes::FailedToDecodePayload;
        let message = "hello world";
        let basic_radius =
            PingError::new_with_message(error_code, message.as_bytes().to_vec()).unwrap();
        let custom_payload = CustomPayload::from(basic_radius);
        let pong = Pong {
            enr_seq: 1,
            custom_payload,
        };
        let pong = Message::Pong(pong);

        let encoded: Vec<u8> = pong.clone().into();
        let encoded = hex_encode(encoded);
        let expected_encoded =
            "0x0101000000000000000c000000ffff0600000002000600000068656c6c6f20776f726c64";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex_decode(&encoded).unwrap()).unwrap();
        assert_eq!(decoded, pong);
    }
}
