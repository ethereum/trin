use ssz::Encode;
use ssz_derive::{Decode, Encode};

use crate::types::{
    distance::Distance, ping_extensions::CustomPayloadExtensionsFormat, portal_wire::CustomPayload,
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
