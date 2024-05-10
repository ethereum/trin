use alloy_primitives::{keccak256, Address, B256, U256, U64};
use alloy_rlp::{
    length_of_length, Decodable, Encodable, Error as RlpError, Header as RlpHeader, RlpDecodable,
    RlpEncodable, EMPTY_STRING_CODE,
};
use bytes::{Buf, Bytes};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, SECP256K1,
};
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

    pub fn get_transaction_sender_address(&self, encode_chain_id: bool) -> anyhow::Result<Address> {
        let signature_hash = self.signature_hash(encode_chain_id);

        let (r, s, odd_y_parity) = match self {
            Transaction::Legacy(tx) => {
                let odd_y_parity = if encode_chain_id {
                    tx.v.byte(0) - 37
                } else {
                    tx.v.byte(0) - 27
                };
                (tx.r, tx.s, odd_y_parity)
            }
            Transaction::AccessList(tx) => (tx.r, tx.s, tx.y_parity.byte(0)),
            Transaction::EIP1559(tx) => (tx.r, tx.s, tx.y_parity.byte(0)),
            Transaction::Blob(tx) => (tx.r, tx.s, tx.y_parity.byte(0)),
        };

        let mut sig: [u8; 65] = [0; 65];
        sig[0..32].copy_from_slice(&r.to_be_bytes::<32>());
        sig[32..64].copy_from_slice(&s.to_be_bytes::<32>());
        sig[64] = odd_y_parity;
        let sig =
            RecoverableSignature::from_compact(&sig[0..64], RecoveryId::from_i32(sig[64] as i32)?)?;

        let public = SECP256K1.recover_ecdsa(
            &Message::from_digest_slice(signature_hash.as_slice())?,
            &sig,
        )?;
        let hash = keccak256(&public.serialize_uncompressed()[1..]);
        Ok(Address::from_slice(&hash[12..]))
    }

    pub fn signature_hash(&self, encode_chain_id: bool) -> B256 {
        match self {
            Transaction::Legacy(tx) => tx.signature_hash(encode_chain_id),
            Transaction::AccessList(tx) => tx.signature_hash(),
            Transaction::EIP1559(tx) => tx.signature_hash(),
            Transaction::Blob(tx) => tx.signature_hash(),
        }
    }

    pub fn encode_with_envelope(&self, out: &mut dyn bytes::BufMut, with_header: bool) {
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

    pub fn signature_hash(&self, encode_chain_id: bool) -> B256 {
        let mut buf = Vec::<u8>::new();
        let mut list = Vec::<u8>::new();
        self.nonce.encode(&mut list);
        self.gas_price.encode(&mut list);
        self.gas.encode(&mut list);
        self.to.encode(&mut list);
        self.value.encode(&mut list);
        self.data.encode(&mut list);
        if encode_chain_id {
            1u64.encode(&mut list);
            0x00u8.encode(&mut list);
            0x00u8.encode(&mut list);
        }
        let header = RlpHeader {
            list: true,
            payload_length: list.len(),
        };
        header.encode(&mut buf);
        buf.extend_from_slice(&list);
        keccak256(&buf)
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

    pub fn signature_hash(&self) -> B256 {
        let mut buf = Vec::<u8>::new();
        let mut list = Vec::<u8>::new();
        self.nonce.encode(&mut list);
        self.gas_price.encode(&mut list);
        self.gas_limit.encode(&mut list);
        self.to.encode(&mut list);
        self.value.encode(&mut list);
        self.data.encode(&mut list);
        self.access_list.encode(&mut list);
        1u64.encode(&mut list);
        0x00u8.encode(&mut list);
        0x00u8.encode(&mut list);
        let header = RlpHeader {
            list: true,
            payload_length: list.len(),
        };
        header.encode(&mut buf);
        buf.extend_from_slice(&list);
        keccak256(&buf)
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

    pub fn signature_hash(&self) -> B256 {
        let mut buf = Vec::<u8>::new();
        let mut list = Vec::<u8>::new();
        self.nonce.encode(&mut list);
        self.max_priority_fee_per_gas.encode(&mut list);
        self.max_fee_per_gas.encode(&mut list);
        self.gas_limit.encode(&mut list);
        self.to.encode(&mut list);
        self.value.encode(&mut list);
        self.data.encode(&mut list);
        self.access_list.encode(&mut list);
        1u64.encode(&mut list);
        0x00u8.encode(&mut list);
        0x00u8.encode(&mut list);
        let header = RlpHeader {
            list: true,
            payload_length: list.len(),
        };
        header.encode(&mut buf);
        buf.extend_from_slice(&list);
        keccak256(&buf)
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

    pub fn signature_hash(&self) -> B256 {
        let mut buf = Vec::<u8>::new();
        let mut list = Vec::<u8>::new();
        self.nonce.encode(&mut list);
        self.max_priority_fee_per_gas.encode(&mut list);
        self.max_fee_per_gas.encode(&mut list);
        self.gas_limit.encode(&mut list);
        self.to.encode(&mut list);
        self.value.encode(&mut list);
        self.data.encode(&mut list);
        self.access_list.encode(&mut list);
        self.max_fee_per_blob_gas.encode(&mut list);
        self.blob_versioned_hashes.encode(&mut list);
        1u64.encode(&mut list);
        0x00u8.encode(&mut list);
        0x00u8.encode(&mut list);
        let header = RlpHeader {
            list: true,
            payload_length: list.len(),
        };
        header.encode(&mut buf);
        buf.extend_from_slice(&list);
        keccak256(&buf)
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
#[allow(clippy::unwrap_used)]
mod tests {
    use alloy_rlp::Decodable;

    use crate::{types::execution::transaction::Transaction, utils::bytes::hex_decode};

    #[rstest::rstest]
    // Block 46170 https://etherscan.io/tx/0x9e6e19637bb625a8ff3d052b7c2fe57dc78c55a15d258d77c43d5a9c160b0384
    #[case(
        "0xf86d8085746a52880082520894c93f2250589a6563f5359051c1ea25746549f0d889208686e75e903bc000801ba034b6fdc33ea520e8123cf5ac4a9ff476f639cab68980cd9366ccae7aef437ea0a0e517caa5f50e27ca0d1e9a92c503b4ccb039680c6d9d0c71203ed611ea4feb33",
        false,
        "0x0aa924d917fd61675076e5456610c166d62aecf4685318febcf25bab0f63b779",
        "0x63ac545c991243fa18aec41d4f6f598e555015dc",
    )]
    // Block 100004 https://etherscan.io/tx/0x6f12399cc2cb42bed5b267899b08a847552e8c42a64f5eb128c1bcbd1974fb0c
    #[case(
        "0xf86d19850cb5bea61483015f9094d9666150a9da92d9108198a4072970805a8b3428884563918244f40000801ba0b23adc880d3735e4389698dddc953fb02f1fa9b57e84d3510a2a4b3597ac2486a04e856f95c4e2828933246fb4765a5bfd2ca5959840643bef0e80b4e3a243d064",
        false,
        "0x9e669fcad535566e5b69acbceb660c636886ac655f1afcb5686aebf820f52ca2",
        "0xcf00a85f3826941e7a25bfcf9aac575d40410852",
    )]
    // Block 3000000 https://etherscan.io/tx/0xb95ab9484280074f7b8c6a3cf5ffe2bf0c39168433adcdedc1aacd10d994d95a
    #[case(
        "0xf8708310aa038504a817c80083015f9094e7268aadb21f48a3b65f0880b6b9480217995979880dfe6c5bd5fa6ff08026a0a186e1a20b3973a29d28d0cddb205ff8b9e670cff1d3e794cd4de1b08b5a8562a0429c2166e893a646cb3b5faf1216ee4c7d99e3957ae145036ca68dec0bcb5f57",
        true,
        "0xd5f76f3a1f7eebadc04d702334445d261d24831d6bfef61e3974bcdb4f015c68",
        "0xea674fdde714fd979de3edf0f56aa9716b898ec8"
    )]
    fn test_legacy_get_sender_address_from_transaction(
        #[case] transaction: &str,
        #[case] post_eip155: bool,
        #[case] signature: &str,
        #[case] sender_address: &str,
    ) {
        let transaction_rlp = hex_decode(transaction).unwrap();
        let transaction: Transaction =
            Decodable::decode(&mut transaction_rlp.as_slice()).expect("error decoding transaction");
        assert_eq!(
            format!("{:?}", transaction.signature_hash(post_eip155)),
            signature
        );
        assert_eq!(
            format!(
                "{:?}",
                transaction
                    .get_transaction_sender_address(post_eip155)
                    .unwrap()
            ),
            sender_address
        );
    }
}
