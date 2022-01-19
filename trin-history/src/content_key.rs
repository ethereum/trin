use sha2::{Digest, Sha256};
use ssz::{self, Decode, Encode};
use ssz_derive::{Decode, Encode};
use trin_core::portalnet::types::content_key::OverlayContentKey;

#[derive(Clone, Debug, Decode, Encode)]
#[ssz(enum_behaviour = "union")]
pub enum HistoryContentKey {
    BlockHeader(BlockHeader),
    BlockBody(BlockBody),
    BlockReceipts(BlockReceipts),
}

#[derive(Clone, Debug, Decode, Encode)]
pub struct BlockHeader {
    chain_id: u16,
    block_hash: [u8; 32],
}

#[derive(Clone, Debug, Decode, Encode)]
pub struct BlockBody {
    chain_id: u16,
    block_hash: [u8; 32],
}

#[derive(Clone, Debug, Decode, Encode)]
pub struct BlockReceipts {
    chain_id: u16,
    block_hash: [u8; 32],
}

#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for HistoryContentKey {
    fn into(self) -> Vec<u8> {
        self.as_ssz_bytes()
    }
}

impl TryFrom<Vec<u8>> for HistoryContentKey {
    type Error = &'static str;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        match HistoryContentKey::from_ssz_bytes(&value) {
            Ok(key) => Ok(key),
            Err(_err) => Err("Unable to decode SSZ"),
        }
    }
}

impl OverlayContentKey for HistoryContentKey {
    fn content_id(&self) -> [u8; 32] {
        let mut sha256 = Sha256::new();
        sha256.update(self.as_ssz_bytes());
        sha256.finalize().into()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use hex;

    const BLOCK_HASH: [u8; 32] = [
        0xd1, 0xc3, 0x90, 0x62, 0x4d, 0x3b, 0xd4, 0xe4, 0x09, 0xa6, 0x1a, 0x85, 0x8e, 0x5d, 0xcc,
        0x55, 0x17, 0x72, 0x9a, 0x91, 0x70, 0xd0, 0x14, 0xa6, 0xc9, 0x65, 0x30, 0xd6, 0x4d, 0xd8,
        0x62, 0x1d,
    ];

    #[test]
    fn block_header() {
        let expected_content_key =
            "000f00d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d";
        let expected_content_id: [u8; 32] = [
            0x21, 0x37, 0xf1, 0x85, 0xb7, 0x13, 0xa6, 0x0d, 0xd1, 0x19, 0x0e, 0x65, 0x0d, 0x01,
            0x22, 0x7b, 0x4f, 0x94, 0xec, 0xdd, 0xc9, 0xc9, 0x54, 0x78, 0xe2, 0xc5, 0x91, 0xc4,
            0x05, 0x57, 0xda, 0x99,
        ];

        let header = BlockHeader {
            chain_id: 15,
            block_hash: BLOCK_HASH,
        };

        let key = HistoryContentKey::BlockHeader(header);
        let encoded: Vec<u8> = key.clone().into();

        assert_eq!(hex::decode(expected_content_key).unwrap(), encoded);
        assert_eq!(expected_content_id, key.content_id());
    }

    #[test]
    fn block_body() {
        let expected_content_key =
            "011400d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d";
        let expected_content_id: [u8; 32] = [
            0x1c, 0x60, 0x46, 0x47, 0x5f, 0x07, 0x72, 0x13, 0x27, 0x74, 0xab, 0x54, 0x91, 0x73,
            0xca, 0x84, 0x87, 0xbe, 0xa0, 0x31, 0xce, 0x53, 0x9c, 0xad, 0x8e, 0x99, 0x0c, 0x08,
            0xdf, 0x58, 0x02, 0xca,
        ];

        let body = BlockBody {
            chain_id: 20,
            block_hash: BLOCK_HASH,
        };

        let key = HistoryContentKey::BlockBody(body);
        let encoded: Vec<u8> = key.clone().into();

        assert_eq!(hex::decode(expected_content_key).unwrap(), encoded);
        assert_eq!(expected_content_id, key.content_id());
    }

    #[test]
    fn block_receipts() {
        let expected_content_key =
            "020400d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d";
        let expected_content_id: [u8; 32] = [
            0xaa, 0x39, 0xe1, 0x42, 0x3e, 0x92, 0xf5, 0xa6, 0x67, 0xac, 0xe5, 0xb7, 0x9c, 0x2c,
            0x98, 0xad, 0xbf, 0xd7, 0x9c, 0x05, 0x5d, 0x89, 0x1d, 0x0b, 0x9c, 0x49, 0xc4, 0x0f,
            0x81, 0x65, 0x63, 0xb2,
        ];

        let body = BlockReceipts {
            chain_id: 4,
            block_hash: BLOCK_HASH,
        };

        let key = HistoryContentKey::BlockReceipts(body);
        let encoded: Vec<u8> = key.clone().into();

        assert_eq!(hex::decode(expected_content_key).unwrap(), encoded);
        assert_eq!(expected_content_id, key.content_id());
    }
}
