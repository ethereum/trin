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

    pub fn field_len(&self) -> usize {
        match self {
            Self::Legacy(tx) => tx.fields_len(),
            Self::AccessList(tx) => tx.fields_len(),
            Self::EIP1559(tx) => tx.fields_len(),
            Self::Blob(tx) => tx.fields_len(),
        }
    }

    pub fn encode_with_envelope(&self, out: &mut dyn bytes::BufMut, with_header: bool) {
        match self {
            Self::Legacy(tx) => tx.encode(out),
            Self::AccessList(tx) => {
                if with_header {
                    let payload_length = tx.fields_len();
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
                if with_header {
                    let payload_length = tx.fields_len();
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
                if with_header {
                    let payload_length = tx.fields_len();
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

    pub fn decode_enveloped_transactions(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        // at least one byte needs to be present
        if buf.is_empty() {
            return Err(RlpError::InputTooShort);
        }
        let original_encoding = *buf;
        let header = RlpHeader::decode(buf)?;
        let value = &mut &buf[..header.payload_length];
        buf.advance(header.payload_length);
        if !header.list {
            let id = TransactionId::try_from(value[0])
                .map_err(|_| RlpError::Custom("Unknown transaction id"))?;
            value.advance(1);
            match id {
                TransactionId::EIP1559 => Ok(Self::EIP1559(EIP1559Transaction::decode(value)?)),
                TransactionId::AccessList => {
                    Ok(Self::AccessList(AccessListTransaction::decode(value)?))
                }
                TransactionId::Legacy => {
                    unreachable!("Legacy transactions should be wrapped in a list")
                }
                TransactionId::Blob => Ok(Self::Blob(BlobTransaction::decode(value)?)),
            }
        } else {
            Ok(Self::Legacy(LegacyTransaction::decode(
                &mut &original_encoding[..(header.payload_length + header.length())],
            )?))
        }
    }
}

impl Encodable for Transaction {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        self.encode_with_envelope(out, false)
    }

    fn length(&self) -> usize {
        let length = self.field_len();
        let length = match &self {
            Transaction::Legacy(_) => length,
            Transaction::AccessList(_) | Transaction::EIP1559(_) | Transaction::Blob(_) => {
                1 + length_of_length(length) + length
            }
        };

        length_of_length(length) + length
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

#[cfg(test)]
mod test {
    use crate::utils::bytes::hex_encode;

    use super::*;

    #[test]
    fn legacy_encode_decode() {
        let tx = Transaction::Legacy(LegacyTransaction {
            nonce: 0x18.try_into().unwrap(),
            gas_price: 0xfa56ea00u64.try_into().unwrap(),
            gas: 119902.try_into().unwrap(),
            to: ToAddress::Exists(Address::from_slice(&hex_decode("0x06012c8cf97bead5deae237070f9587f8e7a266d").unwrap())),
            value: U256::from(0x1c6bf526340000u64),
            data: hex_decode("0xf7d8c88300000000000000000000000000000000000000000000000000000000000cee6100000000000000000000000000000000000000000000000000000000000ac3e1").unwrap().into(),
            v: 37.try_into().unwrap(),
            r: U256::from_be_bytes::<32>(hex_decode("0x2a378831cf81d99a3f06a18ae1b6ca366817ab4d88a70053c41d7a8f0368e031").unwrap().try_into().unwrap()),
            s: U256::from_be_bytes::<32>(hex_decode("0x450d831a05b6e418724436c05c155e0a1b7b921015d0fbc2f667aed709ac4fb5").unwrap().try_into().unwrap()),
        });
        let expected_hash = B256::from_slice(
            &hex_decode("0xbb3a336e3f823ec18197f1e13ee875700f08f03e2cab75f0d0b118dabb44cba0")
                .unwrap(),
        );

        let buf = alloy_rlp::encode(&tx);

        let hash = keccak256(&buf);

        let decoded = Transaction::decode(&mut &buf[..]).unwrap();

        assert_eq!(tx, decoded);
        assert_eq!(expected_hash, hash);
    }

    #[test]
    fn access_list_encode_decode() {
        let tx = Transaction::AccessList(AccessListTransaction {
            chain_id: 0x1.try_into().unwrap(),
            nonce: 0xbc985.try_into().unwrap(),
            gas_price: 0x84d119895u64.try_into().unwrap(),
            gas_limit: 0x7a120.try_into().unwrap(),
            to: ToAddress::Exists(Address::from_slice(
                &hex_decode("0xb50f27bd6e1e19365e9e843dc3db376808f85747").unwrap(),
            )),
            value: 0x244469b75a8000u128.try_into().unwrap(),
            data: "".into(),
            access_list: AccessList::default(),
            y_parity: 0.try_into().unwrap(),
            r: U256::from_be_bytes::<32>(
                hex_decode("0xb222efdbd94f45a88d0ce92031a7ccb546a4859384f65e371b566a4646b2fdd9")
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
            s: U256::from_be_bytes::<32>(
                hex_decode("0x02721bbcd7dcb3cca3b023b4dc67f23aa2de1d4efe8e8d36b5e422b355da0912")
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
        });

        let expected_hash = B256::from_slice(
            &hex_decode("0xd7d37adcf13d2af706dd33432798be898d9324f01c8100c5cc73c1985c89a5af")
                .unwrap(),
        );

        let buf = alloy_rlp::encode(&tx);
        let hash = keccak256(&buf);

        let decoded = Transaction::decode(&mut &buf[..]).unwrap();
        assert_eq!(tx, decoded);
        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn eip1559_encode_decode() {
        let tx = Transaction::EIP1559(EIP1559Transaction {
            chain_id: 1.try_into().unwrap(),
            nonce: 0x42.try_into().unwrap(),
            gas_limit: 44386.try_into().unwrap(),
            to: ToAddress::Exists(Address::from_slice(&hex_decode("0x6069a6c32cf691f5982febae4faf8a6f3ab2f0f6").unwrap())),
            value: U256::ZERO,
            data: Bytes::from(hex_decode("0xa22cb4650000000000000000000000005eee75727d804a2b13038928d36f8b188945a57a0000000000000000000000000000000000000000000000000000000000000000").unwrap()),
            max_fee_per_gas: 0x4a817c800u64.try_into().unwrap(),
            max_priority_fee_per_gas: 0x3b9aca00u64.try_into().unwrap(),
            access_list: AccessList::default(),
            r: U256::from_be_bytes::<32>(hex_decode("0x840cfc572845f5786e702984c2a582528cad4b49b2a10b9db1be7fca90058565").unwrap().try_into().unwrap()),
            s: U256::from_be_bytes::<32>(hex_decode("0x25e7109ceb98168d95b09b18bbf6b685130e0562f233877d492b94eee0c5b6d1").unwrap().try_into().unwrap()),
            y_parity: 0x0.try_into().unwrap(),
        });

        let expected_hash: alloy_primitives::FixedBytes<32> = B256::from_slice(
            &hex_decode("0x0ec0b6a2df4d87424e5f6ad2a654e27aaeb7dac20ae9e8385cc09087ad532ee0")
                .unwrap(),
        );

        let buf = alloy_rlp::encode(&tx);
        println!("{:?}", hex_encode(&buf));
        let hash = keccak256(&buf);

        let decoded = Transaction::decode(&mut &buf[..]).unwrap();
        assert_eq!(tx, decoded);
        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn blob_encode_decode() {
        let tx = Transaction::Blob(BlobTransaction {
            chain_id: 1.try_into().unwrap(),
            nonce: 0xb377.try_into().unwrap(),
            max_priority_fee_per_gas: 0x59055e5eu64.try_into().unwrap(),
            max_fee_per_gas: 0xd09dc3000u128.try_into().unwrap(),
            gas_limit: 0x4c4b40.try_into().unwrap(),
            to: ToAddress::Exists(Address::from_slice(
                &hex_decode("0xd19d4b5d358258f05d7b411e21a1460d11b0876f").unwrap(),
            )),
            value: 0x0.try_into().unwrap(),
            data: Bytes::from(hex_decode("0x2d3c12e5014ee50a775d52d6c2a237c019eea1c0e2656431fbfaf770b71ecccb27b4d1310133ebfb09d965bb16608165012a4d6a381ef24d9acfcafc6e1548ab837664b201c578547a356e041e636b785b13c94fc897ce059b73ad15701cda1f60e4518e000000000000000000000000000000000000000000000000000000000035b54c000000000000000000000000000000000000000000000000000000000035b59c04f7c2b7e0cffebe50b9db5d7deaae8e8d490a4997e49fbd09405d2408015a013ebd7fee0628a625b655c48aca89db9b0b9310ee9c951cdac1dcef5afe3695d300000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000180000000000000000000000000000000000000000000000000000000000000003081ea4cd121164b0cfab3e36b38466f002574ffbe995eeccdf275ef22cec9fbddc94de069d2bf7ebc4a4a2ba91a8c86ac000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030ae3a3ee976de41aa9abbbfba1f9a78a93d8ed351406ea207f5c1f766ccaee118bca5ff293e0ccb0d222fbfced41cf2da00000000000000000000000000000000").unwrap()),
            access_list: Default::default(),
            max_fee_per_blob_gas: 0xd09dc3000u128.try_into().unwrap(),
            blob_versioned_hashes: vec![B256::from_slice(
                &hex_decode("0x019903b23ce40774be59b6075368a4d0c020a0a5af6d620654d3ca31e46b91af").unwrap(),
            )],
            y_parity: 1.try_into().unwrap(),
            r: U256::from_be_bytes::<32>(
                hex_decode("0x3ebfa3874956fe8ac3016838de2e742abc2f5b301df3f1ab91e7ed6d3e708ddd")
                    .unwrap()
                    .try_into()
                    .unwrap()),
            s: U256::from_be_bytes::<32>(
                hex_decode("0x2d6354ee6d39fce2c0602bef8766161498b69d52e29abd5acf1d838cbde339dc").unwrap().try_into().unwrap())
        });

        let expected_hash = B256::from_slice(
            &hex_decode("0x028b71a298242d2c6edf64d6e15baccbe21d173016d0de7e5a828fd283d5fc4f")
                .unwrap(),
        );

        let buf = alloy_rlp::encode(&tx);
        let hash = keccak256(&buf);

        let decoded = Transaction::decode(&mut &buf[..]).unwrap();
        assert_eq!(tx, decoded);
        assert_eq!(hash, expected_hash);
    }
}
