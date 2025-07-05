use crate::{
    BlockBody, ContentValue, ContentValueError, HistoryContentKey, RawContentValue, Receipts,
};

/// A Portal History content value.
pub enum HistoryContentValue {
    BlockBody(BlockBody),
    Receipts(Receipts),
}

/// A content value used in Portal History network
impl ContentValue for HistoryContentValue {
    type TContentKey = HistoryContentKey;

    fn encode(&self) -> RawContentValue {
        todo!()
    }

    fn decode(_key: &Self::TContentKey, _buf: &[u8]) -> Result<Self, ContentValueError> {
        todo!()
    }
}
