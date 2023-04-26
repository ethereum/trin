use ethereum_types::Address;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
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

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct EncodableWithdrawalList {
    pub list: Vec<Withdrawal>,
}

impl Decodable for EncodableWithdrawalList {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let list = rlp
            .into_iter()
            .map(|wd| rlp::decode(wd.as_raw()))
            .collect::<Result<Vec<Withdrawal>, _>>()?;
        Ok(Self { list })
    }
}

impl Encodable for EncodableWithdrawalList {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append_list(&self.list);
    }
}
