mod id_indexed_v1;
pub mod sql;
pub mod store;
mod usage_stats;
mod utils;

use rusqlite::types::{FromSql, FromSqlError, ValueRef};
use strum::{AsRefStr, Display, EnumString};

pub use id_indexed_v1::{IdIndexedV1Store, IdIndexedV1StoreConfig};
pub use store::VersionedContentStore;
pub use utils::create_store;

/// The type of the content that is stored.
///
/// Types don't have to be compatible (e.g. portal network content key/value
/// vs. light clients updates). Compatible types might be able to use the same
/// `StoreVersion` while not compatible might not.
#[derive(Clone, Debug, Display, Eq, PartialEq, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum ContentType {
    History,
    State,
}

/// The version of the store. There should be exactly one implementation of the
/// `VersionedContentStore` for each version (referenced in the comment).
///
/// Versions don't have to be compatible with one another, because they can store
/// completely different type of content (e.g. portal network content key/value
/// vs. light client updates). Compatible versions might implement logic for
/// transitioning from one version to another (towards newer version).
#[derive(Clone, Debug, Display, Eq, PartialEq, EnumString, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum StoreVersion {
    /// The store designed for content-id, content-key and content-value objects.
    /// The content from different subnetwork (expressed with `ContentType`)
    /// uses different table. NOTE: implementation is in progress.
    IdIndexedV1,
    /// The original SQLite version of the history storage store.
    LegacyHistory,
}

impl FromSql for StoreVersion {
    fn column_result(value: ValueRef<'_>) -> Result<Self, FromSqlError> {
        let text = value.as_str()?;
        StoreVersion::try_from(text).map_err(|err| FromSqlError::Other(err.into()))
    }
}
