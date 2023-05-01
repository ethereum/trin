use ethereum_types::Address;
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, RlpDecodable, RlpEncodable)]
pub struct Withdrawal {
    #[serde(deserialize_with = "string_to_u64")]
    pub index: u64,
    #[serde(deserialize_with = "string_to_u64")]
    pub validator_index: u64,
    pub address: Address,
    #[serde(deserialize_with = "string_to_u64")]
    pub amount: u64,
}

fn string_to_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    s.parse::<u64>().map_err(serde::de::Error::custom)
}
