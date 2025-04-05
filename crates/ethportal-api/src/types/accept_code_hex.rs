use serde::{Deserializer, Serializer};
use serde_utils::hex::PrefixedHexVisitor;
use ssz_types::VariableList;

use super::accept_code::{AcceptCode, AcceptCodeList};
use crate::utils::bytes::hex_encode;

pub fn serialize<S>(accept_code_list: &AcceptCodeList, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let bytes: Vec<u8> = accept_code_list
        .0
        .iter()
        .map(|&code| u8::from(code))
        .collect();
    let hex_string = hex_encode(&bytes);
    serializer.serialize_str(&hex_string)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<AcceptCodeList, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = deserializer.deserialize_str(PrefixedHexVisitor)?;
    let accept_code_list = bytes.into_iter().map(AcceptCode::from).collect::<Vec<_>>();
    Ok(AcceptCodeList(VariableList::from(accept_code_list)))
}
