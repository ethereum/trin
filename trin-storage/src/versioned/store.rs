use crate::error::ContentStoreError;

use super::{ContentType, StoreVersion};

/// A trait for the versioned content store. Instance of it should be created using
/// `create_store` function.
pub trait VersionedContentStore: Sized {
    type Config;

    /// Returns the version of the store.
    fn version() -> StoreVersion;

    /// Migrates content from previous version to the new version.
    fn migrate_from(
        content_type: &ContentType,
        old_version: StoreVersion,
        config: &Self::Config,
    ) -> Result<(), ContentStoreError>;

    /// Creates the instance of the store. This shouldn't be used directly. Store should be
    /// created using `create_store` function.
    fn create(content_type: ContentType, config: Self::Config) -> Result<Self, ContentStoreError>;
}
