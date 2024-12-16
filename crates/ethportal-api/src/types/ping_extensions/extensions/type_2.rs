use ssz::Encode;
use ssz_derive::{Decode, Encode};

use crate::types::{
    distance::Distance, ping_extensions::custom_payload_format::CustomPayloadExtensionsFormat,
    portal_wire::CustomPayload,
};

#[derive(PartialEq, Debug, Clone, Encode, Decode)]
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
        CustomPayload::from(
            CustomPayloadExtensionsFormat {
                r#type: 2,
                payload: history_radius.as_ssz_bytes().into(),
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
    use crate::types::{distance::Distance, ping_extensions::decode::DecodedExtension};

    #[test]
    fn test_history_radius() {
        let data_radius = Distance::from(U256::from(42));
        let history_radius = HistoryRadius::new(data_radius, 42);
        let custom_payload = CustomPayload::from(history_radius.clone());

        let decoded_extension = DecodedExtension::try_from(custom_payload).unwrap();

        if let DecodedExtension::HistoryRadius(decoded_history_radius) = decoded_extension {
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
}
