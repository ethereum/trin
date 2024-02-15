pub mod sql;
pub mod store;
mod utils;

use rusqlite::types::{FromSql, FromSqlError, ValueRef};
use strum::{AsRefStr, Display, EnumIter, EnumString};

pub use store::VersionedContentStore;
pub use utils::create_store;

#[derive(Copy, Clone, Debug, Display, Eq, PartialEq, EnumString, AsRefStr, EnumIter)]
#[strum(serialize_all = "snake_case")]
pub enum ContentType {
    Beacon,
    History,
    State,
}

#[derive(Copy, Clone, Debug, Display, Eq, PartialEq, EnumString, AsRefStr, EnumIter)]
#[strum(serialize_all = "snake_case")]
pub enum StoreVersion {
    LegacyContentData,
    IdIndexed,
}

impl FromSql for StoreVersion {
    fn column_result(value: ValueRef<'_>) -> Result<Self, FromSqlError> {
        let text = value.as_str()?;
        StoreVersion::try_from(text).map_err(|err| FromSqlError::Other(err.into()))
    }
}
