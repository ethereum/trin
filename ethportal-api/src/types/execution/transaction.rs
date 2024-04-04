use alloy_primitives::{keccak256, Address, B256, U256, U64};
use alloy_rlp::{
    length_of_length, Decodable, Encodable, Error as RlpError, Header as RlpHeader, RlpDecodable,
    RlpEncodable, EMPTY_STRING_CODE,
};
use bytes::{Buf, Bytes};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};

use super::receipts::TransactionId;
use crate::utils::bytes::hex_decode;

#[derive(Eq, Debug, Clone, PartialEq)]
pub enum Transaction {
    Legacy(LegacyTransaction),
    AccessList(AccessListTransaction),
    EIP1559(EIP1559Transaction),
    Blob(BlobTransaction),
}

impl Transaction {
    /// Returns the Keccak-256 hash of the header.
    pub fn hash(&self) -> B256 {
        keccak256(alloy_rlp::encode(self))
    }
}

impl Encodable for Transaction {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        // we don't wrap versioned transactions with a string header
        let with_header = false;
        match self {
            Self::Legacy(tx) => tx.encode(out),
            Self::AccessList(tx) => {
                let payload_length = tx.fields_len();
                if with_header {
                    RlpHeader {
                        list: false,
                        payload_length: 1 + length_of_length(payload_length) + payload_length,
                    }
                    .encode(out);
                }
                out.put_u8(TransactionId::AccessList as u8);
                tx.encode(out);
            }
            Self::EIP1559(tx) => {
                let payload_length = tx.fields_len();
                if with_header {
                    RlpHeader {
                        list: false,
                        payload_length: 1 + length_of_length(payload_length) + payload_length,
                    }
                    .encode(out);
                }
                out.put_u8(TransactionId::EIP1559 as u8);
                tx.encode(out);
            }
            Self::Blob(tx) => {
                let payload_length = tx.fields_len();
                if with_header {
                    RlpHeader {
                        list: false,
                        payload_length: 1 + length_of_length(payload_length) + payload_length,
                    }
                    .encode(out);
                }
                out.put_u8(TransactionId::Blob as u8);
                tx.encode(out);
            }
        }
    }
}

impl Decodable for Transaction {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        // at least one byte needs to be present
        if buf.is_empty() {
            return Err(RlpError::InputTooShort);
        }
        let id = TransactionId::try_from(buf[0])
            .map_err(|_| RlpError::Custom("Unknown transaction id"))?;
        match id {
            TransactionId::EIP1559 => {
                Ok(Self::EIP1559(EIP1559Transaction::decode(&mut &buf[1..])?))
            }
            TransactionId::AccessList => Ok(Self::AccessList(AccessListTransaction::decode(
                &mut &buf[1..],
            )?)),
            TransactionId::Legacy => Ok(Self::Legacy(LegacyTransaction::decode(buf)?)),
            TransactionId::Blob => Ok(Self::Blob(BlobTransaction::decode(&mut &buf[1..])?)),
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
            TransactionId::Blob => {
                let helper =
                    BlobTransactionHelper::deserialize(obj).map_err(serde::de::Error::custom)?;
                Ok(Self::Blob(helper.into()))
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

impl LegacyTransaction {
    pub fn fields_len(&self) -> usize {
        self.nonce.length()
            + self.gas_price.length()
            + self.gas.length()
            + self.to.length()
            + self.value.length()
            + self.data.length()
            + self.v.length()
            + self.r.length()
            + self.s.length()
    }
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

impl AccessListTransaction {
    pub fn fields_len(&self) -> usize {
        self.chain_id.length()
            + self.nonce.length()
            + self.gas_price.length()
            + self.gas_limit.length()
            + self.to.length()
            + self.value.length()
            + self.data.length()
            + self.access_list.length()
            + self.y_parity.length()
            + self.r.length()
            + self.s.length()
    }
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

impl EIP1559Transaction {
    pub fn fields_len(&self) -> usize {
        self.chain_id.length()
            + self.nonce.length()
            + self.max_priority_fee_per_gas.length()
            + self.max_fee_per_gas.length()
            + self.gas_limit.length()
            + self.to.length()
            + self.value.length()
            + self.data.length()
            + self.access_list.length()
            + self.y_parity.length()
            + self.r.length()
            + self.s.length()
    }
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

#[derive(Eq, Debug, Clone, PartialEq, RlpDecodable, RlpEncodable)]
pub struct BlobTransaction {
    pub chain_id: U256,
    pub nonce: U256,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas_limit: U256,
    pub to: ToAddress,
    pub value: U256,
    pub data: Bytes,
    pub access_list: AccessList,
    pub max_fee_per_blob_gas: U256,
    pub blob_versioned_hashes: Vec<B256>,
    pub y_parity: U64,
    pub r: U256,
    pub s: U256,
}

impl BlobTransaction {
    pub fn fields_len(&self) -> usize {
        self.chain_id.length()
            + self.nonce.length()
            + self.max_priority_fee_per_gas.length()
            + self.max_fee_per_gas.length()
            + self.gas_limit.length()
            + self.to.length()
            + self.value.length()
            + self.data.len()
            + self.access_list.length()
            + self.max_fee_per_blob_gas.length()
            + self.blob_versioned_hashes.length()
            + self.y_parity.length()
            + self.r.length()
            + self.s.length()
    }
}

#[derive(Eq, Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlobTransactionHelper {
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
    pub max_fee_per_blob_gas: U256,
    pub blob_versioned_hashes: Vec<B256>,
    #[serde(rename(deserialize = "v"))]
    pub y_parity: U64,
    pub r: U256,
    pub s: U256,
}

#[allow(clippy::from_over_into)]
impl Into<BlobTransaction> for BlobTransactionHelper {
    fn into(self) -> BlobTransaction {
        BlobTransaction {
            chain_id: self.chain_id,
            nonce: self.nonce,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            max_fee_per_gas: self.max_fee_per_gas,
            gas_limit: self.gas_limit,
            to: self.to,
            value: self.value,
            data: self.data.0,
            max_fee_per_blob_gas: self.max_fee_per_blob_gas,
            blob_versioned_hashes: self.blob_versioned_hashes,
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
    Exists(Address),
}

impl<'de> Deserialize<'de> for ToAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Option<String> = Deserialize::deserialize(deserializer)?;
        match s {
            None => Ok(Self::Empty),
            Some(val) => Ok(Self::Exists(Address::from_slice(
                &hex_decode(&val).map_err(serde::de::Error::custom)?,
            ))),
        }
    }
}

impl Encodable for ToAddress {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        match self {
            ToAddress::Empty => {
                out.put_u8(EMPTY_STRING_CODE);
            }
            ToAddress::Exists(addr) => {
                addr.0.encode(out);
            }
        }
    }
}

impl Decodable for ToAddress {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        if let Some(&first) = buf.first() {
            if first == EMPTY_STRING_CODE {
                buf.advance(1);
                Ok(ToAddress::Empty)
            } else {
                Ok(ToAddress::Exists(Address::decode(buf)?))
            }
        } else {
            Err(RlpError::InputTooShort)
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
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let list: Vec<AccessListItem> = Decodable::decode(buf)?;
        Ok(Self { list })
    }
}

impl Encodable for AccessList {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        self.list.encode(out);
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Deserialize, RlpDecodable, RlpEncodable)]
#[serde(rename_all = "camelCase")]
pub struct AccessListItem {
    pub address: Address,
    pub storage_keys: Vec<B256>,
}
