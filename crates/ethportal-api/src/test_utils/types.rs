use serde::{Deserialize, Serialize};

use crate::{
    types::execution::header_with_proof::HeaderWithProof, ContentValue, ContentValueError,
    LegacyHistoryContentKey, LegacyHistoryContentValue, OverlayContentKey, RawContentValue,
};

/// A common type used in test files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentItem<K: OverlayContentKey> {
    pub content_key: K,
    #[serde(rename = "content_value")]
    pub raw_content_value: RawContentValue,
}

impl<K: OverlayContentKey> ContentItem<K> {
    pub fn content_value<V: ContentValue<TContentKey = K>>(&self) -> Result<V, ContentValueError> {
        V::decode(&self.content_key, &self.raw_content_value)
    }
}

impl ContentItem<LegacyHistoryContentKey> {
    /// Decodes content value as HeaderWithProof.
    ///
    /// Panics if content value is not HeaderWithProof.
    pub fn content_value_as_header_with_proof(&self) -> HeaderWithProof {
        let LegacyHistoryContentValue::BlockHeaderWithProof(header_with_proof) =
            self.content_value().unwrap()
        else {
            panic!(
                "Expected BlockHeaderWithProof content value. Actual {}",
                self.raw_content_value
            );
        };
        header_with_proof
    }
}
