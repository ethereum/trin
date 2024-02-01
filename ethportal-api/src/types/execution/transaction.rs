use bytes::Bytes;
use ethereum_types::{H160, H256, U256, U64};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};

use super::receipts::TransactionId;
use crate::utils::bytes::hex_decode;

#[derive(Eq, Debug, Clone, PartialEq)]
pub enum Transaction {
    Legacy(LegacyTransaction),
    AccessList(AccessListTransaction),
    EIP1559(EIP1559Transaction),
}

impl Transaction {
    /// Returns the Keccak-256 hash of the header.
    pub fn hash(&self) -> H256 {
        keccak_hash::keccak(rlp::encode(self))
    }
}

impl Encodable for Transaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            Self::Legacy(tx) => tx.rlp_append(s),
            Self::AccessList(tx) => {
                let mut stream = RlpStream::new();
                tx.rlp_append(&mut stream);
                let encoded = [&[TransactionId::AccessList as u8], stream.as_raw()].concat();
                s.append_raw(&encoded, 1);
            }
            Self::EIP1559(tx) => {
                let mut stream = RlpStream::new();
                tx.rlp_append(&mut stream);
                let encoded = [&[TransactionId::EIP1559 as u8], stream.as_raw()].concat();
                s.append_raw(&encoded, 1);
            }
        }
    }
}

impl Decodable for Transaction {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        // at least one byte needs to be present
        if rlp.as_raw().is_empty() {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        let id = TransactionId::try_from(rlp.as_raw()[0])
            .map_err(|_| DecoderError::Custom("Unknown transaction id"))?;
        match id {
            TransactionId::EIP1559 => Ok(Self::EIP1559(rlp::decode(&rlp.as_raw()[1..])?)),
            TransactionId::AccessList => Ok(Self::AccessList(rlp::decode(&rlp.as_raw()[1..])?)),
            TransactionId::Legacy => Ok(Self::Legacy(rlp::decode(rlp.as_raw())?)),
        }
    }
}

impl<'de> Deserialize<'de> for Transaction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut obj: Value = Deserialize::deserialize(deserializer)?;
        let tx_id =
            TransactionId::try_from(obj["type"].clone()).map_err(serde::de::Error::custom)?;
        // Inject chain id into json response, since it's not included
        match obj {
            Value::Object(mut val) => {
                val.extend([("chain_id".to_string(), json!("0x1"))]);
                obj = Value::Object(val);
            }
            _ => return Err(serde::de::Error::custom("Invalid transaction id")),
        }
        match tx_id {
            TransactionId::Legacy => {
                let helper =
                    LegacyTransactionHelper::deserialize(obj).map_err(serde::de::Error::custom)?;
                Ok(Self::Legacy(helper.into()))
            }
            TransactionId::AccessList => {
                let helper = AccessListTransactionHelper::deserialize(obj)
                    .map_err(serde::de::Error::custom)?;
                Ok(Self::AccessList(helper.into()))
            }
            TransactionId::EIP1559 => {
                let helper =
                    EIP1559TransactionHelper::deserialize(obj).map_err(serde::de::Error::custom)?;
                Ok(Self::EIP1559(helper.into()))
            }
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct LegacyTransaction {
    pub nonce: U256,
    pub gas_price: U256,
    pub gas: U256,
    pub to: ToAddress,
    pub value: U256,
    pub data: Bytes,
    pub v: U64,
    pub r: U256,
    pub s: U256,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyTransactionHelper {
    pub nonce: U256,
    pub gas_price: U256,
    pub gas: U256,
    pub to: ToAddress,
    pub value: U256,
    #[serde(rename(deserialize = "input"))]
    pub data: JsonBytes,
    pub v: U64,
    pub r: U256,
    pub s: U256,
}

#[allow(clippy::from_over_into)]
impl Into<LegacyTransaction> for LegacyTransactionHelper {
    fn into(self) -> LegacyTransaction {
        LegacyTransaction {
            nonce: self.nonce,
            gas_price: self.gas_price,
            gas: self.gas,
            to: self.to,
            value: self.value,
            data: self.data.0,
            v: self.v,
            r: self.r,
            s: self.s,
        }
    }
}

#[derive(Eq, Debug, Clone, PartialEq, RlpDecodable, RlpEncodable)]
pub struct AccessListTransaction {
    pub chain_id: U256,
    pub nonce: U256,
    pub gas_price: U256,
    pub gas_limit: U256,
    pub to: ToAddress,
    pub value: U256,
    pub data: Bytes,
    pub access_list: AccessList,
    pub y_parity: U64,
    pub r: U256,
    pub s: U256,
}

#[derive(Eq, Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccessListTransactionHelper {
    pub chain_id: U256,
    pub nonce: U256,
    pub gas_price: U256,
    #[serde(rename(deserialize = "gas"))]
    pub gas_limit: U256,
    pub to: ToAddress,
    pub value: U256,
    #[serde(rename(deserialize = "input"))]
    pub data: JsonBytes,
    pub access_list: Vec<AccessListItem>,
    #[serde(rename(deserialize = "v"))]
    pub y_parity: U64,
    pub r: U256,
    pub s: U256,
}

#[allow(clippy::from_over_into)]
impl Into<AccessListTransaction> for AccessListTransactionHelper {
    fn into(self) -> AccessListTransaction {
        AccessListTransaction {
            chain_id: self.chain_id,
            nonce: self.nonce,
            gas_price: self.gas_price,
            gas_limit: self.gas_limit,
            to: self.to,
            value: self.value,
            data: self.data.0,
            access_list: AccessList {
                list: self.access_list,
            },
            y_parity: self.y_parity,
            r: self.r,
            s: self.s,
        }
    }
}

#[derive(Eq, Debug, Clone, PartialEq, RlpDecodable, RlpEncodable)]
pub struct EIP1559Transaction {
    pub chain_id: U256,
    pub nonce: U256,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas_limit: U256,
    pub to: ToAddress,
    pub value: U256,
    pub data: Bytes,
    pub access_list: AccessList,
    pub y_parity: U64,
    pub r: U256,
    pub s: U256,
}

#[derive(Eq, Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EIP1559TransactionHelper {
    pub chain_id: U256,
    pub nonce: U256,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    #[serde(rename(deserialize = "gas"))]
    pub gas_limit: U256,
    pub to: ToAddress,
    pub value: U256,
    #[serde(rename(deserialize = "input"))]
    pub data: JsonBytes,
    pub access_list: Vec<AccessListItem>,
    #[serde(rename(deserialize = "v"))]
    pub y_parity: U64,
    pub r: U256,
    pub s: U256,
}

#[allow(clippy::from_over_into)]
impl Into<EIP1559Transaction> for EIP1559TransactionHelper {
    fn into(self) -> EIP1559Transaction {
        EIP1559Transaction {
            chain_id: self.chain_id,
            nonce: self.nonce,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            max_fee_per_gas: self.max_fee_per_gas,
            gas_limit: self.gas_limit,
            to: self.to,
            value: self.value,
            data: self.data.0,
            access_list: AccessList {
                list: self.access_list,
            },
            y_parity: self.y_parity,
            r: self.r,
            s: self.s,
        }
    }
}

/// Enum to represent the "to" field in a tx. Which can be an address, or Null if a contract is
/// created.
#[derive(Default, Eq, Debug, Clone, PartialEq)]
pub enum ToAddress {
    #[default]
    Empty,
    Exists(H160),
}

impl<'de> Deserialize<'de> for ToAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Option<String> = Deserialize::deserialize(deserializer)?;
        match s {
            None => Ok(Self::Empty),
            Some(val) => Ok(Self::Exists(H160::from_slice(
                &hex_decode(&val).map_err(serde::de::Error::custom)?,
            ))),
        }
    }
}

impl Encodable for ToAddress {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            ToAddress::Empty => {
                s.append_internal(&"");
            }
            ToAddress::Exists(addr) => {
                s.append_internal(addr);
            }
        }
    }
}

impl Decodable for ToAddress {
    fn decode(rlp: &Rlp<'_>) -> Result<Self, DecoderError> {
        match rlp.is_empty() {
            true => Ok(ToAddress::Empty),
            false => Ok(ToAddress::Exists(rlp::decode(rlp.as_raw())?)),
        }
    }
}

#[derive(Eq, Debug, Default, Clone, PartialEq, RlpDecodable, RlpEncodable)]
pub struct JsonBytes(Bytes);

impl<'de> Deserialize<'de> for JsonBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex_decode(&s).map_err(serde::de::Error::custom)?;
        Ok(Self(Bytes::copy_from_slice(&bytes)))
    }
}

impl From<Bytes> for JsonBytes {
    fn from(val: Bytes) -> Self {
        Self(val)
    }
}

#[allow(clippy::from_over_into)]
impl Into<Bytes> for JsonBytes {
    fn into(self) -> Bytes {
        self.0
    }
}

#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct AccessList {
    pub list: Vec<AccessListItem>,
}

impl Decodable for AccessList {
    fn decode(rlp_obj: &Rlp) -> Result<Self, DecoderError> {
        let list: Result<Vec<AccessListItem>, DecoderError> =
            rlp_obj.iter().map(|v| rlp::decode(v.as_raw())).collect();
        Ok(Self { list: list? })
    }
}

impl Encodable for AccessList {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.append_list(&self.list);
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Deserialize, RlpDecodable, RlpEncodable)]
#[serde(rename_all = "camelCase")]
pub struct AccessListItem {
    pub address: H160,
    pub storage_keys: Vec<H256>,
}
