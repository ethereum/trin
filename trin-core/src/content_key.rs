use crate::portalnet::types::content_key::OverlayContentKey;
use sha2::{Digest, Sha256};
use ssz::{self, Decode, Encode};
use ssz_derive::{Decode, Encode};

/// A content key in the history overlay network.
#[derive(Clone, Debug, Decode, Encode)]
#[ssz(enum_behaviour = "union")]
pub enum HistoryContentKey {
    /// A block header.
    BlockHeader(BlockHeader),
}

/// A key for a block header.
#[derive(Clone, Debug, Decode, Encode)]
pub struct BlockHeader {
    /// Chain identifier.
    pub chain_id: u16,
    /// Hash of the block.
    pub block_hash: [u8; 32],
}

// Silence clippy to avoid implementing newtype pattern on imported type
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
