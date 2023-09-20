//! Serialize `VariableList<u8, N>` as 0x-prefixed hex string.

use serde::{Deserializer, Serializer};
use serde_utils::hex::{self, PrefixedHexVisitor};
use ssz_types::typenum::Unsigned;
use ssz_types::VariableList;

pub fn serialize<S, N>(bytes: &VariableList<u8, N>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    N: Unsigned,
{
    serializer.serialize_str(&hex::encode(&**bytes))
}

pub fn deserialize<'de, D, N>(deserializer: D) -> Result<VariableList<u8, N>, D::Error>
where
    D: Deserializer<'de>,
    N: Unsigned,
{
    let bytes = deserializer.deserialize_str(PrefixedHexVisitor)?;
    VariableList::new(bytes)
        .map_err(|e| serde::de::Error::custom(format!("invalid variable list: {:?}", e)))
}
