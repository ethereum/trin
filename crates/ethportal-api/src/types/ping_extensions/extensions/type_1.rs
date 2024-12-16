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
    use crate::types::{distance::Distance, ping_extensions::decode::DecodedExtension};

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
}
