use ethportal_api::{ContentValue, ContentValueError, OverlayContentKey, RawContentValue};
use serde::{Deserialize, Serialize};

/// The common test vectors type.
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
