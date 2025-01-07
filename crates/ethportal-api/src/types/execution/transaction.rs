use alloy::{
    primitives::{keccak256, Address, B256, U256, U64},
    rlp::{
        self, Decodable, Encodable, RlpDecodable, RlpEncodable, EMPTY_LIST_CODE, EMPTY_STRING_CODE,
    },
};
use bytes::{Buf, BufMut, Bytes};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, SECP256K1,
};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};

use super::receipts::TransactionId;
use crate::utils::bytes::hex_decode;

/// The Transaction Envelope type.
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
        keccak256(rlp::encode(self))
    }

    pub fn get_transaction_sender_address(&self) -> anyhow::Result<Address> {
        let (r, s, odd_y_parity, is_eip155) = match self {
            Transaction::Legacy(tx) => {
                let v = tx.v.byte(0);
                let (odd_y_parity, is_eip155) = if v < 35 {
                    (v - 27, false)
                } else {
                    (v - 37, true)
                };
                (tx.r, tx.s, odd_y_parity, is_eip155)
            }
            Transaction::AccessList(tx) => (tx.r, tx.s, tx.y_parity.byte(0), true),
            Transaction::EIP1559(tx) => (tx.r, tx.s, tx.y_parity.byte(0), true),
            Transaction::Blob(tx) => (tx.r, tx.s, tx.y_parity.byte(0), true),
        };

        let signature_hash = self.signature_hash(is_eip155);

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
}

impl Encodable for Transaction {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        match self {
            Self::Legacy(tx) => tx.encode(out),
            Self::AccessList(tx) => {
                out.put_u8(TransactionId::AccessList as u8);
                tx.encode(out);
            }
            Self::EIP1559(tx) => {
                out.put_u8(TransactionId::EIP1559 as u8);
                tx.encode(out);
            }
            Self::Blob(tx) => {
                out.put_u8(TransactionId::Blob as u8);
                tx.encode(out);
            }
        }
    }

    fn length(&self) -> usize {
        match self {
            Self::Legacy(tx) => tx.length(),
            Self::AccessList(tx) => 1 + tx.length(),
            Self::EIP1559(tx) => 1 + tx.length(),
            Self::Blob(tx) => 1 + tx.length(),
        }
    }
}

impl Decodable for Transaction {
    fn decode(buf: &mut &[u8]) -> rlp::Result<Self> {
        // at least one byte needs to be present
        if buf.is_empty() {
            return Err(rlp::Error::InputTooShort);
        }
        let id = TransactionId::try_from(buf[0])
            .map_err(|_| rlp::Error::Custom("Unknown transaction id"))?;
        match id {
            TransactionId::Blob => {
                buf.advance(1);
                BlobTransaction::decode(buf).map(Self::Blob)
            }
            TransactionId::EIP1559 => {
                buf.advance(1);
                EIP1559Transaction::decode(buf).map(Self::EIP1559)
            }
            TransactionId::AccessList => {
                buf.advance(1);
                AccessListTransaction::decode(buf).map(Self::AccessList)
            }
            TransactionId::Legacy => LegacyTransaction::decode(buf).map(Self::Legacy),
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

/// The wrapper around [Transaction] structure, that has different RLP encoding.
///
/// In most cases, RLP encoding of [Transaction] object is the correct one, but in some rare cases,
/// this one is used instead. If unsure, use basic type.
///
/// The RLP encoding of this type is done in a following way:
///
/// - Legacy transactions are always encoded in the same way: `rlp(tx)`.
/// - Other transactions are encoded as: `rlp(type + rlp(tx))` (where `+` represents concatenation)
///   - `type` is a single byte represending the transaction type
///
/// The basic type differs in the way it encodes non-legacy transaction. The basic type doesn't have
/// extra RLP wrapper around it, meaning it's just: `type + rlp(tx)`.
pub struct TransactionWithRlpHeader(pub Transaction);

impl Encodable for TransactionWithRlpHeader {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        let (transaction_id, tx): (TransactionId, Box<dyn Encodable>) = match &self.0 {
            // Legacy transaction is encoded as is (no header)
            Transaction::Legacy(tx) => {
                tx.encode(out);
                return;
            }
            Transaction::AccessList(tx) => (TransactionId::AccessList, Box::new(tx)),
            Transaction::EIP1559(tx) => (TransactionId::EIP1559, Box::new(tx)),
            Transaction::Blob(tx) => (TransactionId::Blob, Box::new(tx)),
        };
        rlp::Header {
            list: false,
            payload_length: 1 + tx.length(),
        }
        .encode(out);
        out.put_u8(transaction_id as u8);
        tx.encode(out);
    }

    fn length(&self) -> usize {
        let payload_length = match &self.0 {
            Transaction::Legacy(tx) => {
                // Legacy transaction is encoded as is (no header)
                return tx.length();
            }
            Transaction::AccessList(tx) => 1 + tx.length(),
            Transaction::EIP1559(tx) => 1 + tx.length(),
            Transaction::Blob(tx) => 1 + tx.length(),
        };
        // Add Header length
        payload_length + rlp::length_of_length(payload_length)
    }
}

impl Decodable for TransactionWithRlpHeader {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        // at least one byte needs to be present
        if buf.is_empty() {
            return Err(rlp::Error::InputTooShort);
        }

        // Legacy transaction is encoded as list. Others are wrapped in a string header.
        if buf[0] >= EMPTY_LIST_CODE {
            return LegacyTransaction::decode(buf).map(|tx| Self(Transaction::Legacy(tx)));
        }

        let mut payload_view = rlp::Header::decode_bytes(buf, /* is_list= */ false)?;
        let payload_length = payload_view.remaining();

        if payload_view.is_empty() {
            return Err(rlp::Error::InputTooShort);
        }

        let id = TransactionId::try_from(payload_view[0])
            .map_err(|_| rlp::Error::Custom("Unknown transaction id"))?;
        payload_view.advance(1);
        let tx = match id {
            TransactionId::Blob => Transaction::Blob(BlobTransaction::decode(&mut payload_view)?),
            TransactionId::EIP1559 => {
                Transaction::EIP1559(EIP1559Transaction::decode(&mut payload_view)?)
            }
            TransactionId::AccessList => {
                Transaction::AccessList(AccessListTransaction::decode(&mut payload_view)?)
            }
            TransactionId::Legacy => {
                return Err(rlp::Error::Custom(
                    "Legacy transactions should be wrapped in a list",
                ));
            }
        };

        if payload_view.has_remaining() {
            let consumed = payload_length - payload_view.remaining();
            return Err(rlp::Error::ListLengthMismatch {
                expected: payload_length,
                got: consumed,
            });
        }

        Ok(Self(tx))
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
        let header = rlp::Header {
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
    pub fn signature_hash(&self) -> B256 {
        let mut buf = Vec::<u8>::new();
        let mut list = Vec::<u8>::new();
        1u64.encode(&mut list);
        self.nonce.encode(&mut list);
        self.gas_price.encode(&mut list);
        self.gas_limit.encode(&mut list);
        self.to.encode(&mut list);
        self.value.encode(&mut list);
        self.data.encode(&mut list);
        self.access_list.encode(&mut list);
        let header = rlp::Header {
            list: true,
            payload_length: list.len(),
        };
        buf.put_u8(1);
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
    pub fn signature_hash(&self) -> B256 {
        let mut buf = Vec::<u8>::new();
        let mut list = Vec::<u8>::new();
        1u64.encode(&mut list);
        self.nonce.encode(&mut list);
        self.max_priority_fee_per_gas.encode(&mut list);
        self.max_fee_per_gas.encode(&mut list);
        self.gas_limit.encode(&mut list);
        self.to.encode(&mut list);
        self.value.encode(&mut list);
        self.data.encode(&mut list);
        self.access_list.encode(&mut list);
        let header = rlp::Header {
            list: true,
            payload_length: list.len(),
        };
        buf.put_u8(2);
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
    pub fn signature_hash(&self) -> B256 {
        let mut buf = Vec::<u8>::new();
        let mut list = Vec::<u8>::new();
        1u64.encode(&mut list);
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
        let header = rlp::Header {
            list: true,
            payload_length: list.len(),
        };
        buf.put_u8(3);
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
    fn decode(buf: &mut &[u8]) -> rlp::Result<Self> {
        if let Some(&first) = buf.first() {
            if first == EMPTY_STRING_CODE {
                buf.advance(1);
                Ok(ToAddress::Empty)
            } else {
                Ok(ToAddress::Exists(Address::decode(buf)?))
            }
        } else {
            Err(rlp::Error::InputTooShort)
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
    fn decode(buf: &mut &[u8]) -> rlp::Result<Self> {
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
    use super::*;

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
    // Block 2675000 https://etherscan.io/tx/0x427b0b68b1ccc46b01d99ed399b61c4ae681e22216035eb6953afc83ef463e17
    #[case(
        "0xf86c02850e33e22200825208947329c8dbafaef13c3388de01015ea855e13723a28816ebf60a31618800801ca028e95ddd1849293d85341dc12a7ce2cb04c49b492d0b6afeea8553035bdc2ee1a01f3e9490b23ac10d2332310babfd201d4f6a30512cb55b5163f66ce3e082a8d3",
        false,
        "0x2d2bea519c4b02a71a7aaa40e402df443c00ff12d4cda62371b6fabb32ef4c95",
        "0xf7bdb487a46241f78ebabc18e251a828e48da502"
    )]
    // Block 3000000 https://etherscan.io/tx/0xb95ab9484280074f7b8c6a3cf5ffe2bf0c39168433adcdedc1aacd10d994d95a
    #[case(
        "0xf8708310aa038504a817c80083015f9094e7268aadb21f48a3b65f0880b6b9480217995979880dfe6c5bd5fa6ff08026a0a186e1a20b3973a29d28d0cddb205ff8b9e670cff1d3e794cd4de1b08b5a8562a0429c2166e893a646cb3b5faf1216ee4c7d99e3957ae145036ca68dec0bcb5f57",
        true,
        "0xd5f76f3a1f7eebadc04d702334445d261d24831d6bfef61e3974bcdb4f015c68",
        "0xea674fdde714fd979de3edf0f56aa9716b898ec8"
    )]
    // Block 12244145 https://etherscan.io/tx/0x851bad0415758075a1eb86776749c829b866d43179c57c3e4a4b9359a0358231
    #[case(
        "0x01f9039f018218bf85105e34df0083048a949410a0847c2d170008ddca7c3a688124f49363003280b902e4c11695480000000000000000000000004b274e4a9af31c20ed4151769a88ffe63d9439960000000000000000000000008510211a852f0c5994051dd85eaef73112a82eb5000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000bad4de000000000000000000000000607816a600000000000000000000000000000000000000000000000000000000000002200000000000000000000000000000000000000000000000000000001146aa2600000000000000000000000000000000000000000000000000000000000001bc9b000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee000000000000000000000000482579f93dc13e6b434e38b5a0447ca543d88a4600000000000000000000000000000000000000000000000000000000000000c42df546f40000000000000000000000004b274e4a9af31c20ed4151769a88ffe63d943996000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000000000000000000000007d93f93d41604572119e4be7757a7a4a43705f080000000000000000000000000000000000000000000000003782dace9d90000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000082b5a61569b5898ac347c82a594c86699f1981aa88ca46a6a00b8e4f27b3d17bdf3714e7c0ca6a8023b37cca556602fce7dc7daac3fcee1ab04bbb3b94c10dec301cc57266db6567aa073efaa1fa6669bdc6f0877b0aeab4e33d18cb08b8877f08931abf427f11bade042177db48ca956feb114d6f5d56d1f5889047189562ec545e1c000000000000000000000000000000000000000000000000000000000000f84ff7946856ccf24beb7ed77f1f24eee5742f7ece5557e2e1a00000000000000000000000000000000000000000000000000000000000000001d694b1dd690cc9af7bb1a906a9b5a94f94191cc553cec080a0d52f3dbcad3530e73fcef6f4a75329b569a8903bf6d8109a960901f251a37af3a00ecf570e0c0ffa6efdc6e6e49be764b6a1a77e47de7bb99e167544ffbbcd65bc",
        true,
        "0x894d999ea27537def37534b3d55df3fed4e1492b31e9f640774432d21cf4512c",
        "0x1ced2cef30d40bb3617f8d455071b69f3b12d06f"
    )]

    fn test_legacy_get_sender_address_from_transaction(
        #[case] transaction: &str,
        #[case] post_eip155: bool,
        #[case] signature: &str,
        #[case] sender_address: &str,
    ) {
        let transaction_rlp = hex_decode(transaction).unwrap();
        let transaction = Transaction::decode(&mut transaction_rlp.as_slice())
            .expect("error decoding transaction");
        assert_eq!(
            format!("{:?}", transaction.signature_hash(post_eip155)),
            signature
        );
        assert_eq!(
            format!(
                "{:?}",
                transaction.get_transaction_sender_address().unwrap()
            ),
            sender_address
        );
    }
}
