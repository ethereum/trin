use ethportal_api::{types::distance::Distance, OverlayContentKey};
use trin_metrics::storage::StorageMetricsReporter;

use crate::{
    error::ContentStoreError, ContentId, ContentStore, PortalStorageConfig, ShouldWeStoreContent,
};

use super::{ContentType, StoreVersion};

/// A trait for the versioned content store. Instance of it should be created using
/// `create_store` function.
pub trait VersionedContentStore: Sized {
    /// Returns the version of the store.
    fn version() -> StoreVersion;

    /// Migrates content from previous version to the new version.
    fn migrate_from(
        content_type: ContentType,
        old_version: StoreVersion,
        config: &PortalStorageConfig,
    ) -> Result<(), ContentStoreError>;

    /// Creates the instance of the store. This shouldn't be used directly. Store should be
    /// created using `create_store` function.
    fn create(
        content_type: ContentType,
        config: PortalStorageConfig,
        metrics: StorageMetricsReporter,
    ) -> Result<Self, ContentStoreError>;

    /// Returns the radius that this store store.
    fn radius(&self) -> Distance;

    /// Returns the distance between store's `node_id` and `content_id`.
    fn distance_to_content_id(&self, content_id: &ContentId) -> Distance;

    /// Returns whether store should store the content.
    fn should_store_content_id(&self, content_id: &ContentId) -> bool {
        self.distance_to_content_id(content_id) <= self.radius()
    }

    /// Inserts the content into the store.
    fn insert<K: OverlayContentKey>(
        &mut self,
        content_key: &K,
        content_value: Vec<u8>,
    ) -> Result<(), ContentStoreError>;

    /// Deletes the content from the store.
    fn delete(&mut self, content_id: &ContentId) -> Result<(), ContentStoreError>;

    /// Prunes the store's content. This can have different meaning to different version of the
    /// store.
    fn prune(&mut self) -> Result<(), ContentStoreError>;

    /// Returns whether store contains content with a given `content_id`.
    fn has_content(&self, content_id: &ContentId) -> Result<bool, ContentStoreError>;

    /// Returns the stored content-key.
    fn lookup_content_key<K: OverlayContentKey>(
        &self,
        content_id: &ContentId,
    ) -> Result<Option<K>, ContentStoreError>;

    /// Returns the stored content-value.
    fn lookup_content_value(
        &self,
        content_id: &ContentId,
    ) -> Result<Option<Vec<u8>>, ContentStoreError>;

    /// Returns the summary info of the store.
    fn get_summary_info(&self) -> String;
}

impl<T: VersionedContentStore> ContentStore for T {
    fn get<K: OverlayContentKey>(&self, key: &K) -> Result<Option<Vec<u8>>, ContentStoreError> {
        self.lookup_content_value(&key.content_id().into())
    }

    fn put<K: OverlayContentKey, V: AsRef<[u8]>>(
        &mut self,
        key: K,
        value: V,
    ) -> Result<(), ContentStoreError> {
        self.insert(&key, value.as_ref().into())
    }

    fn is_key_within_radius_and_unavailable<K: OverlayContentKey>(
        &self,
        key: &K,
    ) -> Result<ShouldWeStoreContent, ContentStoreError> {
        let content_id = ContentId::from(key.content_id());
        if self.should_store_content_id(&content_id) {
            if self.has_content(&content_id)? {
                Ok(ShouldWeStoreContent::AlreadyStored)
            } else {
                Ok(ShouldWeStoreContent::Store)
            }
        } else {
            Ok(ShouldWeStoreContent::NotWithinRadius)
        }
    }

    fn radius(&self) -> Distance {
        self.radius()
    }
}
