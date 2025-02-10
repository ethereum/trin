use ssz::{Decode, Encode};

use crate::{
    types::{
        content_value::ContentValue, network::Subnetwork,
        updated::header_with_proof::HeaderWithProof,
    },
    utils::bytes::hex_encode,
    BlockBody, ContentValueError, HistoryContentKey, RawContentValue, Receipts,
};

/// A Portal History content value.
#[derive(Clone, Debug, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum HistoryContentValue {
    BlockHeaderWithProof(HeaderWithProof),
    BlockBody(BlockBody),
    Receipts(Receipts),
}

impl ContentValue for HistoryContentValue {
    type TContentKey = HistoryContentKey;

    fn encode(&self) -> RawContentValue {
        match self {
            Self::BlockHeaderWithProof(value) => value.as_ssz_bytes().into(),
            Self::BlockBody(value) => value.as_ssz_bytes().into(),
            Self::Receipts(value) => value.as_ssz_bytes().into(),
        }
    }

    fn decode(key: &Self::TContentKey, buf: &[u8]) -> Result<Self, ContentValueError> {
        match key {
            HistoryContentKey::BlockHeaderByHash(_) | HistoryContentKey::BlockHeaderByNumber(_) => {
                if let Ok(value) = HeaderWithProof::from_ssz_bytes(buf) {
                    return Ok(Self::BlockHeaderWithProof(value));
                }
            }
            HistoryContentKey::BlockBody(_) => {
                if let Ok(value) = BlockBody::from_ssz_bytes(buf) {
                    return Ok(Self::BlockBody(value));
                }
            }
            HistoryContentKey::BlockReceipts(_) => {
                if let Ok(value) = Receipts::from_ssz_bytes(buf) {
                    return Ok(Self::Receipts(value));
                }
            }
        }

        Err(ContentValueError::UnknownContent {
            bytes: hex_encode(buf),
            subnetwork: Subnetwork::History,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::HistoryContentValue;

    #[test]
    fn content_value_deserialization_failure_displays_debuggable_data() {
        let key = HistoryContentKey::random().unwrap();
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let item_result = HistoryContentValue::decode(&key, &data);
        let error = item_result.unwrap_err();
        // Test the error Debug representation
        assert_eq!(
            error,
            ContentValueError::UnknownContent {
                bytes: "0x010203040506070809".to_string(),
                subnetwork: Subnetwork::History,
            }
        );
        // Test the error Display representation.
        assert_eq!(
            error.to_string(),
            "could not determine content type of 0x010203040506070809 from History subnetwork"
        );
    }
}
