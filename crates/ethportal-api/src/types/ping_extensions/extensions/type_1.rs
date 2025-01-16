use ssz::Encode;
use ssz_derive::{Decode, Encode};

use crate::types::{
    distance::Distance, ping_extensions::custom_payload_format::CustomPayloadExtensionsFormat,
    portal_wire::CustomPayload,
};

#[derive(PartialEq, Debug, Clone, Encode, Decode)]
pub struct BasicRadius {
    pub data_radius: Distance,
}

impl BasicRadius {
    pub fn new(data_radius: Distance) -> Self {
        Self { data_radius }
    }
}

impl From<BasicRadius> for CustomPayload {
    fn from(basic_radius: BasicRadius) -> Self {
        CustomPayload::from(
            CustomPayloadExtensionsFormat {
                r#type: 1,
                payload: basic_radius.as_ssz_bytes().into(),
            }
            .as_ssz_bytes(),
        )
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::U256;
    use ssz::Decode;

    use super::*;
    use crate::{
        types::{
            distance::Distance,
            ping_extensions::decode::DecodedExtension,
            portal_wire::{Message, Ping, Pong},
        },
        utils::bytes::{hex_decode, hex_encode},
    };

    #[test]
    fn test_basic_radius() {
        let data_radius = Distance::from(U256::from(42));
        let basic_radius = BasicRadius::new(data_radius);
        let custom_payload = CustomPayload::from(basic_radius.clone());

        let decoded_extension = DecodedExtension::try_from(custom_payload).unwrap();

        if let DecodedExtension::BasicRadius(decoded_basic_radius) = decoded_extension {
            assert_eq!(basic_radius, decoded_basic_radius);
        } else {
            panic!("Decoded extension is not BasicRadius");
        }
    }

    #[test]
    fn test_basic_radius_ssz_round_trip() {
        let data_radius = Distance::from(U256::from(42));
        let basic_radius = BasicRadius::new(data_radius);
        let bytes = basic_radius.as_ssz_bytes();
        let decoded = BasicRadius::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(basic_radius, decoded);
    }

    #[test]
    fn message_encoding_ping_basic_radius() {
        let data_radius = Distance::from(U256::MAX - U256::from(1));
        let basic_radius = BasicRadius::new(data_radius);
        let custom_payload = CustomPayload::from(basic_radius);
        let ping = Ping {
            enr_seq: 1,
            custom_payload,
        };
        let ping = Message::Ping(ping);

        let encoded: Vec<u8> = ping.clone().into();
        let encoded = hex_encode(encoded);
        let expected_encoded = "0x0001000000000000000c000000010006000000feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex_decode(&encoded).unwrap()).unwrap();
        assert_eq!(decoded, ping);
    }

    #[test]
    fn message_encoding_pong_basic_radius() {
        let data_radius = Distance::from(U256::MAX - U256::from(1));
        let basic_radius = BasicRadius::new(data_radius);
        let custom_payload = CustomPayload::from(basic_radius);
        let pong = Pong {
            enr_seq: 1,
            custom_payload,
        };
        let pong = Message::Pong(pong);

        let encoded: Vec<u8> = pong.clone().into();
        let encoded = hex_encode(encoded);
        let expected_encoded = "0x0101000000000000000c000000010006000000feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex_decode(&encoded).unwrap()).unwrap();
        assert_eq!(decoded, pong);
    }
}
