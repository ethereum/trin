use alloy_primitives::U256;
use serde::{ser::SerializeSeq, Deserialize, Deserializer, Serializer};
use serde_json::Value;
use ssz_types::VariableList;

use super::body::{Transaction, Transactions};
use crate::utils::bytes::{hex_decode, hex_encode};

pub fn se_txs_to_hex<S>(value: &Transactions, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut s = serializer.serialize_seq(Some(value.len()))?;
    for val in value {
        s.serialize_element(&hex_encode(val.to_vec()))?;
    }
    s.end()
}

pub fn se_hex_to_number<S>(value: &U256, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string())
}

pub fn de_number_to_u256<'de, D>(deserializer: D) -> Result<U256, D::Error>
where
    D: Deserializer<'de>,
{
    let result: Value = Deserialize::deserialize(deserializer)?;
    let result = match result.as_str() {
        Some(val) => val,
        None => return Err(serde::de::Error::custom("Unable to deserialize u256")),
    };
    let result = U256::from_str_radix(result, 10).map_err(serde::de::Error::custom)?;
    Ok(result)
}

pub fn de_hex_to_txs<'de, D>(deserializer: D) -> Result<Transactions, D::Error>
where
    D: Deserializer<'de>,
{
    let result: Vec<String> = Deserialize::deserialize(deserializer)?;
    let mut txs: Transactions = VariableList::empty();
    for r in result {
        let tx = hex_decode(&r).map_err(serde::de::Error::custom)?;
        let tx = Transaction::from(tx);
        if txs.push(tx).is_err() {
            return Err(serde::de::Error::custom("Unable to deserialize txs"));
        }
    }
    Ok(txs)
}
