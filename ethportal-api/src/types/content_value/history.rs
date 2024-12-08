use ssz::{Decode, Encode};

use crate::{
    types::{
        content_value::ContentValue, execution::header_with_proof::HeaderWithProof,
        network::Subnetwork,
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
    use std::fs;

    use serde_json::Value;

    use super::*;
    use crate::{utils::bytes::hex_decode, HistoryContentValue};

    #[test]
    fn header_with_proof_encode_decode_fluffy() {
        let file =
            fs::read_to_string("../trin-validation/src/assets/fluffy/header_with_proofs.json")
                .unwrap();
        let json: Value = serde_json::from_str(&file).unwrap();
        let json = json.as_object().unwrap();
        for (block_num, obj) in json {
            let block_num: u64 = block_num.parse().unwrap();
            let header_with_proof = obj.get("value").unwrap().as_str().unwrap();
            let header_with_proof_encoded = hex_decode(header_with_proof).unwrap();
            let header_with_proof =
                HeaderWithProof::from_ssz_bytes(&header_with_proof_encoded).unwrap();

            assert_eq!(header_with_proof.header.number, block_num);

            let encoded = header_with_proof.as_ssz_bytes();
            assert_eq!(encoded, header_with_proof_encoded);
        }
    }

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
