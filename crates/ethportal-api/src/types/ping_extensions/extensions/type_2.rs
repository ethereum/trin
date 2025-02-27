use serde::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};

use crate::types::{distance::Distance, portal_wire::CustomPayload};

#[derive(PartialEq, Eq, Debug, Clone, Encode, Decode, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryRadius {
    pub data_radius: Distance,
    pub ephemeral_header_count: u16,
}

impl HistoryRadius {
    pub fn new(data_radius: Distance, ephemeral_header_count: u16) -> Self {
        Self {
            data_radius,
            ephemeral_header_count,
        }
    }
}

impl From<HistoryRadius> for CustomPayload {
    fn from(history_radius: HistoryRadius) -> Self {
        CustomPayload::from(history_radius.as_ssz_bytes())
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
            ping_extensions::decode::PingExtension,
            portal_wire::{Message, Ping, Pong},
        },
        utils::bytes::{hex_decode, hex_encode},
    };

    #[test]
    fn test_history_radius() {
        let data_radius = Distance::from(U256::from(42));
        let history_radius = HistoryRadius::new(data_radius, 42);
        let custom_payload = CustomPayload::from(history_radius.clone());

        let decoded_extension = PingExtension::decode_ssz(2, custom_payload).unwrap();

        if let PingExtension::HistoryRadius(decoded_history_radius) = decoded_extension {
            assert_eq!(history_radius, decoded_history_radius);
        } else {
            panic!("Decoded extension is not HistoryRadius");
        }
    }

    #[test]
    fn test_history_radius_ssz_round_trip() {
        let data_radius = Distance::from(U256::from(42));
        let history_radius = HistoryRadius::new(data_radius, 42);
        let bytes = history_radius.as_ssz_bytes();
        let decoded = HistoryRadius::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(bytes.len(), 34);
        assert_eq!(history_radius, decoded);
    }

    #[test]
    fn message_encoding_ping_history_radius() {
        let data_radius = Distance::from(U256::MAX - U256::from(1));
        let ephemeral_header_count = 4242;
        let history_radius = HistoryRadius::new(data_radius, ephemeral_header_count);
        let payload = CustomPayload::from(history_radius);
        let ping = Ping {
            enr_seq: 1,
            payload_type: 2,
            payload,
        };
        let ping = Message::Ping(ping);

        let encoded: Vec<u8> = ping.clone().into();
        let encoded = hex_encode(encoded);
        let expected_encoded = "0x00010000000000000002000e000000feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff9210";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex_decode(&encoded).unwrap()).unwrap();
        assert_eq!(decoded, ping);
    }

    #[test]
    fn message_encoding_pong_history_radius() {
        let data_radius = Distance::from(U256::MAX - U256::from(1));
        let ephemeral_header_count = 4242;
        let history_radius = HistoryRadius::new(data_radius, ephemeral_header_count);
        let payload = CustomPayload::from(history_radius);
        let pong = Pong {
            enr_seq: 1,
            payload_type: 2,
            payload,
        };
        let pong = Message::Pong(pong);

        let encoded: Vec<u8> = pong.clone().into();
        let encoded = hex_encode(encoded);
        let expected_encoded = "0x01010000000000000002000e000000feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff9210";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex_decode(&encoded).unwrap()).unwrap();
        assert_eq!(decoded, pong);
    }
}
