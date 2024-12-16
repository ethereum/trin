use ssz::Encode;
use ssz_derive::{Decode, Encode};

use crate::types::{
    distance::Distance, ping_extensions::CustomPayloadExtensionsFormat, portal_wire::CustomPayload,
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
