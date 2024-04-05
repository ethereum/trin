use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

use alloy_primitives::{Address, Bloom, BloomInput, B256, U256};
use alloy_rlp::{
    length_of_length, Decodable, Encodable, Error as RlpError, Header as RlpHeader, RlpDecodable,
    RlpEncodable,
};
use anyhow::anyhow;
use bytes::{Buf, BufMut, Bytes};
use eth_trie::{EthTrie, MemoryDB, Trie};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

use super::transaction::JsonBytes;
use crate::utils::bytes::hex_decode;

// 2 ^ 14
const MAX_TRANSACTION_COUNT: usize = 16384;

/// Represents the `Receipts` datatype used by the chain history wire protocol
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipts {
    pub receipt_list: Vec<Receipt>,
}

impl Receipts {
    pub fn root(&self) -> anyhow::Result<B256> {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb);

        // Insert receipts into receipts tree
        for (index, receipt) in self.receipt_list.iter().enumerate() {
            let path = alloy_rlp::encode(index);
            let encoded_receipt = alloy_rlp::encode(receipt);
            trie.insert(&path, &encoded_receipt)
                .map_err(|err| anyhow!("Error calculating receipts root: {err:?}"))?;
        }

        trie.root_hash()
            .map_err(|err| anyhow!("Error calculating receipts root: {err:?}"))
    }
}

impl Encodable for Receipts {
    fn encode(&self, out: &mut dyn BufMut) {
        let mut list = Vec::<u8>::new();
        for receipt in &self.receipt_list {
            receipt.encode_with_envelope(&mut list, true);
        }
        let header = RlpHeader {
            list: true,
            payload_length: list.len(),
        };
        header.encode(out);
        out.put_slice(list.as_slice());
    }
}

impl Decodable for Receipts {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let mut bytes = RlpHeader::decode_bytes(buf, true)?;
        let mut receipt_list: Vec<Receipt> = vec![];
        let payload_view = &mut bytes;
        while !payload_view.is_empty() {
            receipt_list.push(Receipt::decode_enveloped_transactions(payload_view)?);
        }
        Ok(Self { receipt_list })
    }
}

impl ssz::Encode for Receipts {
    // note: MAX_LENGTH attributes (defined in portal history spec) are not currently enforced
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let encoded_receipts: Vec<Vec<u8>> =
            self.receipt_list.iter().map(alloy_rlp::encode).collect();
        encoded_receipts.ssz_append(buf);
    }

    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

impl ssz::Decode for Receipts {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let encoded_receipts: Vec<Vec<u8>> =
            ssz::decode_list_of_variable_length_items(bytes, Some(MAX_TRANSACTION_COUNT))?;
        let receipts: Vec<Receipt> = encoded_receipts
            .iter()
            .map(|bytes| Decodable::decode(&mut bytes.as_slice()))
            .collect::<Result<Vec<Receipt>, _>>()
            .map_err(|e| {
                ssz::DecodeError::BytesInvalid(format!(
                    "Receipt list contains invalid receipts: {e:?}",
                ))
            })?;
        Ok(Self {
            receipt_list: receipts,
        })
    }
}

// Deserialize is currently only implemented for BATCHED responses from an execution client
// Used inside portal-bridge
impl<'de> Deserialize<'de> for Receipts {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let obj: Vec<Value> = Deserialize::deserialize(deserializer)?;
        let results: Result<Vec<Receipt>, _> = obj
            .into_iter()
            .map(|mut val| {
                let result = val["result"].take();
                serde_json::from_value(result)
            })
            .collect();
        Ok(Self {
            receipt_list: results.map_err(serde::de::Error::custom)?,
        })
    }
}

// Based on https://github.com/openethereum/openethereum/blob/main/crates/ethcore/types/src/receipt.rs

/// A record of execution for a `LOG` operation.
#[derive(Default, Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct LogEntry {
    /// The address of the contract executing at the point of the `LOG` operation.
    pub address: Address,
    /// The topics associated with the `LOG` operation.
    pub topics: Vec<B256>,
    /// The data associated with the `LOG` operation.
    pub data: Bytes,
}

/// A record of execution for a `LOG` operation.
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, RlpEncodable, RlpDecodable)]
pub struct LogEntryHelper {
    /// The address of the contract executing at the point of the `LOG` operation.
    pub address: Address,
    /// The topics associated with the `LOG` operation.
    pub topics: Vec<B256>,
    /// The data associated with the `LOG` operation.
    pub data: JsonBytes,
}

impl From<LogEntryHelper> for LogEntry {
    fn from(v: LogEntryHelper) -> LogEntry {
        LogEntry {
            address: v.address,
            topics: v.topics,
            data: v.data.into(),
        }
    }
}

impl LogEntry {
    /// Calculates the bloom of this log entry.
    pub fn bloom(&self) -> Bloom {
        self.topics.iter().fold(
            Bloom::from(BloomInput::Raw(self.address.as_slice())),
            |mut b, t| {
                b.accrue(BloomInput::Raw(t.as_slice()));
                b
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionOutcome {
    /// State root is known, before EIP-658 is enabled.
    StateRoot(B256),
    /// Status code is known. EIP-658 rules.
    StatusCode(u8),
}

impl TransactionOutcome {
    pub fn length(&self) -> usize {
        match self {
            Self::StateRoot(_) => 32,
            Self::StatusCode(_) => 1,
        }
    }
}

impl Decodable for TransactionOutcome {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let s = Bytes::decode(buf)?;
        match s.len() {
            32 => Ok(Self::StateRoot(B256::from_slice(&s))),
            1 => Ok(Self::StatusCode(s[0])),
            0 => Ok(Self::StatusCode(0)),
            _ => Err(alloy_rlp::Error::Custom("Invalid transaction outcome")),
        }
    }
}

impl<'de> Deserialize<'de> for TransactionOutcome {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        match s.len() {
            3 => {
                let s = s.trim_start_matches("0x");
                Ok(Self::StatusCode(
                    s.parse::<u8>().map_err(serde::de::Error::custom)?,
                ))
            }
            66 => Ok(Self::StateRoot(B256::from_slice(
                &hex_decode(&s).map_err(serde::de::Error::custom)?,
            ))),
            _ => Err(serde::de::Error::custom("Invalid transaction outcome")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyReceipt {
    pub cumulative_gas_used: U256,
    pub log_bloom: Bloom,
    pub logs: Vec<LogEntry>,
    pub outcome: TransactionOutcome,
}

impl LegacyReceipt {
    pub fn fields_len(&self) -> usize {
        self.cumulative_gas_used.length()
            + self.log_bloom.length()
            + self.logs.length()
            + self.outcome.length()
    }
}

impl<'de> Deserialize<'de> for LegacyReceipt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = LegacyReceiptHelper::deserialize(deserializer)?;
        Ok(s.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyReceiptHelper {
    pub cumulative_gas_used: U256,
    pub logs_bloom: Bloom,
    pub logs: Vec<LogEntryHelper>,
    #[serde(alias = "root", alias = "status")]
    pub outcome: TransactionOutcome,
}

#[allow(clippy::from_over_into)]
impl Into<LegacyReceipt> for LegacyReceiptHelper {
    fn into(self) -> LegacyReceipt {
        let logs = self.logs.into_iter().map(|v| v.into()).collect();
        LegacyReceipt {
            cumulative_gas_used: self.cumulative_gas_used,
            log_bloom: self.logs_bloom,
            logs,
            outcome: self.outcome,
        }
    }
}

impl LegacyReceipt {
    pub fn new(
        outcome: TransactionOutcome,
        cumulative_gas_used: U256,
        logs: Vec<LogEntry>,
    ) -> Self {
        LegacyReceipt {
            cumulative_gas_used,
            log_bloom: logs.iter().fold(Bloom::default(), |mut b, l| {
                b.accrue_bloom(&l.bloom());
                b
            }),
            logs,
            outcome,
        }
    }
}

impl Decodable for LegacyReceipt {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let rlp_head = RlpHeader::decode(buf)?;
        if !rlp_head.list {
            return Err(RlpError::UnexpectedString);
        }
        Ok(LegacyReceipt {
            outcome: Decodable::decode(buf)?,
            cumulative_gas_used: Decodable::decode(buf)?,
            log_bloom: Decodable::decode(buf)?,
            logs: Decodable::decode(buf)?,
        })
    }
}

impl Encodable for LegacyReceipt {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        let mut list = Vec::<u8>::new();
        match self.outcome {
            TransactionOutcome::StateRoot(ref root) => root.encode(&mut list),
            TransactionOutcome::StatusCode(status_code) => status_code.encode(&mut list),
        }
        self.cumulative_gas_used.encode(&mut list);
        self.log_bloom.encode(&mut list);
        self.logs.encode(&mut list);
        let header = RlpHeader {
            list: true,
            payload_length: list.len(),
        };
        header.encode(out);
        out.put_slice(list.as_slice());
    }
}

#[derive(Eq, Hash, Debug, Copy, Clone, PartialEq)]
#[repr(u8)]
/// The typed transaction ID
pub enum TransactionId {
    Blob = 0x03,
    EIP1559 = 0x02,
    AccessList = 0x01,
    Legacy = 0x00,
}

impl TryFrom<u8> for TransactionId {
    type Error = RlpError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            id if id == TransactionId::EIP1559 as u8 => Ok(Self::EIP1559),
            id if id == TransactionId::AccessList as u8 => Ok(Self::AccessList),
            id if id == TransactionId::Blob as u8 => Ok(Self::Blob),
            id if (id & 0x80) != 0x00 => Ok(Self::Legacy),
            id if id == TransactionId::Legacy as u8 => Ok(Self::Legacy),
            _ => Err(RlpError::Custom(
                "Invalid byte selector for transaction type.",
            )),
        }
    }
}

impl TryFrom<Value> for TransactionId {
    type Error = RlpError;

    fn try_from(val: Value) -> Result<Self, Self::Error> {
        let id = val.as_str().ok_or(RlpError::Custom(
            "Invalid tx id: unable to decode as string.",
        ))?;
        let id = id.trim_start_matches("0x");
        let id = id
            .parse::<u8>()
            .map_err(|_| RlpError::Custom("Invalid tx id: unable to parse u8"))?;
        Self::try_from(id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Receipt {
    Legacy(LegacyReceipt),
    AccessList(LegacyReceipt),
    EIP1559(LegacyReceipt),
    Blob(LegacyReceipt),
}

impl Receipt {
    /// Create a new receipt.
    pub fn new(type_id: TransactionId, legacy_receipt: LegacyReceipt) -> Self {
        //currently we are using same receipt for both legacy and typed transaction
        match type_id {
            TransactionId::EIP1559 => Self::EIP1559(legacy_receipt),
            TransactionId::AccessList => Self::AccessList(legacy_receipt),
            TransactionId::Legacy => Self::Legacy(legacy_receipt),
            TransactionId::Blob => Self::Blob(legacy_receipt),
        }
    }

    pub fn receipt(&self) -> &LegacyReceipt {
        match self {
            Self::Legacy(receipt) => receipt,
            Self::AccessList(receipt) => receipt,
            Self::EIP1559(receipt) => receipt,
            Self::Blob(receipt) => receipt,
        }
    }

    pub fn receipt_mut(&mut self) -> &mut LegacyReceipt {
        match self {
            Self::Legacy(receipt) => receipt,
            Self::AccessList(receipt) => receipt,
            Self::EIP1559(receipt) => receipt,
            Self::Blob(receipt) => receipt,
        }
    }

    fn encode_with_envelope(&self, out: &mut dyn bytes::BufMut, with_header: bool) {
        match self {
            Self::Legacy(receipt) => {
                receipt.encode(out);
            }
            Self::AccessList(receipt) => {
                let payload_length = receipt.fields_len();
                if with_header {
                    RlpHeader {
                        list: false,
                        payload_length: 1 + length_of_length(payload_length) + payload_length,
                    }
                    .encode(out);
                }
                out.put_u8(TransactionId::AccessList as u8);
                receipt.encode(out);
            }
            Self::EIP1559(receipt) => {
                let payload_length = receipt.fields_len();
                if with_header {
                    RlpHeader {
                        list: false,
                        payload_length: 1 + length_of_length(payload_length) + payload_length,
                    }
                    .encode(out);
                }
                out.put_u8(TransactionId::EIP1559 as u8);
                receipt.encode(out);
            }
            Self::Blob(receipt) => {
                let payload_length = receipt.fields_len();
                if with_header {
                    RlpHeader {
                        list: false,
                        payload_length: 1 + length_of_length(payload_length) + payload_length,
                    }
                    .encode(out);
                }
                out.put_u8(TransactionId::Blob as u8);
                receipt.encode(out);
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
                TransactionId::Legacy => {
                    unreachable!("Legacy receipts should be wrapped in a list")
                }
                TransactionId::AccessList => Ok(Self::AccessList(Decodable::decode(value)?)),
                TransactionId::EIP1559 => Ok(Self::EIP1559(Decodable::decode(value)?)),
                TransactionId::Blob => Ok(Self::Blob(Decodable::decode(value)?)),
            }
        } else {
            Ok(Self::Legacy(Decodable::decode(
                &mut &original_encoding[..(header.payload_length + header.length())],
            )?))
        }
    }
}

impl Encodable for Receipt {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        self.encode_with_envelope(out, false)
    }
}

impl Decodable for Receipt {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        // at least one byte needs to be present
        if buf.is_empty() {
            return Err(RlpError::InputTooShort);
        }
        let id = TransactionId::try_from(buf[0])
            .map_err(|_| RlpError::Custom("Unknown transaction id"))?;
        //other transaction types
        match id {
            TransactionId::Legacy => Ok(Self::Legacy(Decodable::decode(buf)?)),
            TransactionId::AccessList => Ok(Self::AccessList(Decodable::decode(&mut &buf[1..])?)),
            TransactionId::EIP1559 => Ok(Self::EIP1559(Decodable::decode(&mut &buf[1..])?)),
            TransactionId::Blob => Ok(Self::Blob(Decodable::decode(&mut &buf[1..])?)),
        }
    }
}

impl<'de> Deserialize<'de> for Receipt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let obj: Value = Deserialize::deserialize(deserializer)?;
        if obj.is_null() {
            return Err(anyhow!("Null receipt found.")).map_err(serde::de::Error::custom);
        }
        let tx_id =
            TransactionId::try_from(obj["type"].clone()).map_err(serde::de::Error::custom)?;
        match tx_id {
            // todo support other receipts
            TransactionId::Legacy => Ok(Receipt::Legacy(
                LegacyReceipt::deserialize(obj).map_err(serde::de::Error::custom)?,
            )),
            TransactionId::AccessList => Ok(Receipt::AccessList(
                LegacyReceipt::deserialize(obj).map_err(serde::de::Error::custom)?,
            )),
            TransactionId::EIP1559 => Ok(Receipt::EIP1559(
                LegacyReceipt::deserialize(obj).map_err(serde::de::Error::custom)?,
            )),
            TransactionId::Blob => Ok(Receipt::Blob(
                LegacyReceipt::deserialize(obj).map_err(serde::de::Error::custom)?,
            )),
        }
    }
}

impl Deref for Receipt {
    type Target = LegacyReceipt;

    fn deref(&self) -> &Self::Target {
        self.receipt()
    }
}

impl DerefMut for Receipt {
    fn deref_mut(&mut self) -> &mut LegacyReceipt {
        self.receipt_mut()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::{str::FromStr, vec};

    use alloy_primitives::U256;
    use serde_json::json;
    use ssz::{Decode, Encode};

    use crate::utils::bytes::hex_encode;

    //
    // Tests using custom generated rlp encoded receipts from block 14764013
    //

    #[test_log::test]
    fn legacy_receipt() {
        let receipt_rlp = hex_decode(RECEIPT_6).unwrap();
        let receipt: Receipt =
            Decodable::decode(&mut receipt_rlp.as_slice()).expect("error decoding receipt");
        // tx link: https://etherscan.io/tx/0x147c84ddb366ae572ce5aa4d815e62de3a151133479fbb414e25d32bd7db9aa5
        assert_eq!(receipt.cumulative_gas_used, U256::from(579367));
        assert_eq!(receipt.logs, []);
        assert_eq!(receipt.outcome, TransactionOutcome::StatusCode(1));
        let encoded = alloy_rlp::encode(receipt);
        assert_eq!(encoded, receipt_rlp);
    }

    #[test_log::test]
    fn typed_receipt() {
        let receipt_rlp = hex_decode(RECEIPT_0).unwrap();
        let receipt: Receipt =
            Decodable::decode(&mut receipt_rlp.as_slice()).expect("error decoding receipt");
        // tx link: https://etherscan.io/tx/0x163dae461ab32787eaecdad0748c9cf5fe0a22b443bc694efae9b80e319d9559
        assert_eq!(receipt.cumulative_gas_used, U256::from(189807));
        assert_eq!(receipt.logs.len(), 7);
        assert_eq!(receipt.outcome, TransactionOutcome::StatusCode(1));
        let encoded = alloy_rlp::encode(receipt);
        assert_eq!(encoded, receipt_rlp);
    }

    #[test_log::test]
    fn cumulative_gas_used() {
        // cumulative gas for last tx in block should match block's gas used
        let receipt_rlp = hex_decode(RECEIPT_18).unwrap();
        let receipt: Receipt =
            Decodable::decode(&mut receipt_rlp.as_slice()).expect("error decoding receipt");
        // https://etherscan.io/block/14764013
        assert_eq!(receipt.cumulative_gas_used, U256::from(1314225));
    }

    #[test_log::test]
    fn calculate_receipts_root() {
        let receipts = Receipts {
            receipt_list: vec![
                Decodable::decode(&mut hex_decode(RECEIPT_0).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_1).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_2).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_3).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_4).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_5).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_6).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_7).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_8).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_9).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_10).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_11).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_12).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_13).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_14).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_15).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_16).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_17).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_18).unwrap().as_slice()).unwrap(),
            ],
        };
        assert_eq!(
            hex_encode(receipts.root().unwrap()),
            EXPECTED_RECEIPTS_ROOT.to_owned()
        );
    }

    #[test_log::test]
    fn ssz_encoding_decoding_receipts() {
        let receipts = Receipts {
            receipt_list: vec![
                Decodable::decode(&mut hex_decode(RECEIPT_0).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_1).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_2).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_3).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_4).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_5).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_6).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_7).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_8).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_9).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_10).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_11).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_12).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_13).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_14).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_15).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_16).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_17).unwrap().as_slice()).unwrap(),
                Decodable::decode(&mut hex_decode(RECEIPT_18).unwrap().as_slice()).unwrap(),
            ],
        };
        let encoded = receipts.as_ssz_bytes();

        let expected: Vec<u8> =
            std::fs::read("../test_assets/mainnet/receipts_14764013.bin").unwrap();
        assert_eq!(hex_encode(&encoded), hex_encode(expected));

        let decoded = Receipts::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(receipts, decoded);
    }

    //
    // OpenEthereum Tests
    // https://github.com/openethereum/openethereum/blob/main/crates/ethcore/types/src/receipt.rs

    #[test_log::test]
    fn no_state_root() {
        let expected = hex_decode("0xf90162a02f697d671e9ae4ee24a43c4b0d7e15f1cb4ba6de1561120d43b9a4e8c4a8a6ee83040caeb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000f838f794dcf421d093428b096ca501a7cd1a740855a7976fc0a00000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let receipt = Receipt::new(
            TransactionId::Legacy,
            LegacyReceipt::new(
                TransactionOutcome::StateRoot(
                    B256::from_str(
                        "2f697d671e9ae4ee24a43c4b0d7e15f1cb4ba6de1561120d43b9a4e8c4a8a6ee",
                    )
                    .unwrap(),
                ),
                U256::from_str_radix("40cae", 16).unwrap(),
                vec![LogEntry {
                    address: Address::from_str("dcf421d093428b096ca501a7cd1a740855a7976f").unwrap(),
                    topics: vec![],
                    data: Bytes::from(vec![0u8; 32]),
                }],
            ),
        );
        let encoded = alloy_rlp::encode(&receipt);
        assert_eq!(encoded, expected);
        let decoded: Receipt =
            Decodable::decode(&mut encoded.as_slice()).expect("decoding receipt failed");
        assert_eq!(decoded, receipt);
    }

    #[test_log::test]
    fn basic_legacy() {
        let expected = hex_decode("0xf90162a02f697d671e9ae4ee24a43c4b0d7e15f1cb4ba6de1561120d43b9a4e8c4a8a6ee83040caeb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000f838f794dcf421d093428b096ca501a7cd1a740855a7976fc0a00000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let receipt = Receipt::new(
            TransactionId::Legacy,
            LegacyReceipt::new(
                TransactionOutcome::StateRoot(
                    B256::from_str(
                        "2f697d671e9ae4ee24a43c4b0d7e15f1cb4ba6de1561120d43b9a4e8c4a8a6ee",
                    )
                    .unwrap(),
                ),
                U256::from_str_radix("40cae", 16).unwrap(),
                vec![LogEntry {
                    address: Address::from_str("dcf421d093428b096ca501a7cd1a740855a7976f").unwrap(),
                    topics: vec![],
                    data: Bytes::from(vec![0u8; 32]),
                }],
            ),
        );
        let encoded = alloy_rlp::encode(&receipt);
        assert_eq!(encoded, expected);
        let decoded: Receipt =
            Decodable::decode(&mut encoded.as_slice()).expect("decoding receipt failed");
        assert_eq!(decoded, receipt);
    }

    #[test_log::test]
    fn basic_access_list() {
        let expected = hex_decode("0x01f90162a02f697d671e9ae4ee24a43c4b0d7e15f1cb4ba6de1561120d43b9a4e8c4a8a6ee83040caeb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000f838f794dcf421d093428b096ca501a7cd1a740855a7976fc0a00000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let receipt = Receipt::new(
            TransactionId::AccessList,
            LegacyReceipt::new(
                TransactionOutcome::StateRoot(
                    B256::from_str(
                        "2f697d671e9ae4ee24a43c4b0d7e15f1cb4ba6de1561120d43b9a4e8c4a8a6ee",
                    )
                    .unwrap(),
                ),
                U256::from_str_radix("40cae", 16).unwrap(),
                vec![LogEntry {
                    address: Address::from_str("dcf421d093428b096ca501a7cd1a740855a7976f").unwrap(),
                    topics: vec![],
                    data: Bytes::from(vec![0u8; 32]),
                }],
            ),
        );
        let encoded = alloy_rlp::encode(&receipt);
        assert_eq!(&encoded, &expected);
        let decoded: Receipt =
            Decodable::decode(&mut encoded.as_slice()).expect("decoding receipt failed");
        assert_eq!(decoded, receipt);
    }

    #[test_log::test]
    fn basic_eip1559() {
        let expected = hex_decode("0x02f90162a02f697d671e9ae4ee24a43c4b0d7e15f1cb4ba6de1561120d43b9a4e8c4a8a6ee83040caeb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000f838f794dcf421d093428b096ca501a7cd1a740855a7976fc0a00000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let receipt = Receipt::new(
            TransactionId::EIP1559,
            LegacyReceipt::new(
                TransactionOutcome::StateRoot(
                    B256::from_str(
                        "2f697d671e9ae4ee24a43c4b0d7e15f1cb4ba6de1561120d43b9a4e8c4a8a6ee",
                    )
                    .unwrap(),
                ),
                U256::from_str_radix("40cae", 16).unwrap(),
                vec![LogEntry {
                    address: Address::from_str("dcf421d093428b096ca501a7cd1a740855a7976f").unwrap(),
                    topics: vec![],
                    data: Bytes::from(vec![0u8; 32]),
                }],
            ),
        );
        let encoded = alloy_rlp::encode(&receipt);
        assert_eq!(&encoded, &expected);
        let decoded: Receipt =
            Decodable::decode(&mut encoded.as_slice()).expect("decoding receipt failed");
        assert_eq!(decoded, receipt);
    }

    #[test_log::test]
    fn status_code() {
        let expected = hex_decode("0xf901428083040caeb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000f838f794dcf421d093428b096ca501a7cd1a740855a7976fc0a00000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let receipt = Receipt::new(
            TransactionId::Legacy,
            LegacyReceipt::new(
                TransactionOutcome::StatusCode(0),
                U256::from_str_radix("40cae", 16).unwrap(),
                vec![LogEntry {
                    address: Address::from_str("dcf421d093428b096ca501a7cd1a740855a7976f").unwrap(),
                    topics: vec![],
                    data: Bytes::from(vec![0u8; 32]),
                }],
            ),
        );
        let encoded = alloy_rlp::encode(&receipt);
        assert_eq!(&encoded[..], &expected[..]);
        let decoded: Receipt =
            Decodable::decode(&mut encoded.as_slice()).expect("decoding receipt failed");
        assert_eq!(decoded, receipt);
    }

    #[test_log::test]
    fn from_json_legacy() {
        // 0x147c84ddb366ae572ce5aa4d815e62de3a151133479fbb414e25d32bd7db9aa5
        let response = json!({"blockHash": "0x720704f3aa11c53cf344ea069db95cecb81ad7453c8f276b2a1062979611f09c", "blockNumber": "0xe147ed", "contractAddress": null, "cumulativeGasUsed": "0x8d727", "effectiveGasPrice": "0x2aa7599fe2", "from": "0xeb6c4be4b92a52e969f4bf405025d997703d5383", "gasUsed": "0x5208", "logs": [], "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "status": "0x1", "to": "0x4c875e8bd31969f4b753b3ab1611e29f270ba47e", "transactionHash": "0x147c84ddb366ae572ce5aa4d815e62de3a151133479fbb414e25d32bd7db9aa5", "transactionIndex": "0x6", "type": "0x0"});
        let receipt: Receipt = serde_json::from_value(response).unwrap();
        let receipt = match receipt {
            Receipt::Legacy(val) => val,
            _ => panic!("invalid test"),
        };
        assert_eq!(
            receipt.cumulative_gas_used,
            U256::from_str_radix("579367", 10).unwrap()
        );
    }

    #[test_log::test]
    fn from_json_typed() {
        //0x163dae461ab32787eaecdad0748c9cf5fe0a22b443bc694efae9b80e319d9559
        let response = json!({"blockHash": "0x720704f3aa11c53cf344ea069db95cecb81ad7453c8f276b2a1062979611f09c", "blockNumber": "0xe147ed", "contractAddress": null, "cumulativeGasUsed": "0x2e56f", "effectiveGasPrice": "0x1b05c3919a", "from": "0xdd19b32a084be0a318f11edb3f7034889c03c51f", "gasUsed": "0x2e56f", "logs": [{"address": "0xdac17f958d2ee523a2206206994597c13d831ec7", "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", "0x000000000000000000000000dd19b32a084be0a318f11edb3f7034889c03c51f", "0x00000000000000000000000074de5d4fcbf63e00296fd95d33236b9794016631"], "data": "0x00000000000000000000000000000000000000000000000000000000979aedeb", "blockNumber": "0xe147ed", "transactionHash": "0x163dae461ab32787eaecdad0748c9cf5fe0a22b443bc694efae9b80e319d9559", "transactionIndex": "0x0", "blockHash": "0x720704f3aa11c53cf344ea069db95cecb81ad7453c8f276b2a1062979611f09c", "logIndex": "0x0", "removed": false}, {"address": "0xdac17f958d2ee523a2206206994597c13d831ec7", "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", "0x00000000000000000000000074de5d4fcbf63e00296fd95d33236b9794016631", "0x00000000000000000000000074c99f3f5331676f6aec2756e1f39b4fc029a83e"], "data": "0x00000000000000000000000000000000000000000000000000000000979aedeb", "blockNumber": "0xe147ed", "transactionHash": "0x163dae461ab32787eaecdad0748c9cf5fe0a22b443bc694efae9b80e319d9559", "transactionIndex": "0x0", "blockHash": "0x720704f3aa11c53cf344ea069db95cecb81ad7453c8f276b2a1062979611f09c", "logIndex": "0x1", "removed": false}, {"address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", "0x00000000000000000000000074c99f3f5331676f6aec2756e1f39b4fc029a83e", "0x0000000000000000000000001111111254fb6c44bac0bed2854e76f90643097d"], "data": "0x00000000000000000000000000000000000000000000000011f8b9803bc57124", "blockNumber": "0xe147ed", "transactionHash": "0x163dae461ab32787eaecdad0748c9cf5fe0a22b443bc694efae9b80e319d9559", "transactionIndex": "0x0", "blockHash": "0x720704f3aa11c53cf344ea069db95cecb81ad7453c8f276b2a1062979611f09c", "logIndex": "0x2", "removed": false}, {"address": "0x74c99f3f5331676f6aec2756e1f39b4fc029a83e", "topics": ["0x1c411e9a96e071241c2f21f7726b17ae89e3cab4c78be50e062b03a9fffbbad1"], "data": "0x0000000000000000000000000000000000000000000000657acd23da825d7df70000000000000000000000000000000000000000000000000000035616e4172a", "blockNumber": "0xe147ed", "transactionHash": "0x163dae461ab32787eaecdad0748c9cf5fe0a22b443bc694efae9b80e319d9559", "transactionIndex": "0x0", "blockHash": "0x720704f3aa11c53cf344ea069db95cecb81ad7453c8f276b2a1062979611f09c", "logIndex": "0x3", "removed": false}, {"address": "0x74c99f3f5331676f6aec2756e1f39b4fc029a83e", "topics": ["0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822", "0x0000000000000000000000001111111254fb6c44bac0bed2854e76f90643097d", "0x0000000000000000000000001111111254fb6c44bac0bed2854e76f90643097d"], "data": "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000979aedeb00000000000000000000000000000000000000000000000011f8b9803bc571240000000000000000000000000000000000000000000000000000000000000000", "blockNumber": "0xe147ed", "transactionHash": "0x163dae461ab32787eaecdad0748c9cf5fe0a22b443bc694efae9b80e319d9559", "transactionIndex": "0x0", "blockHash": "0x720704f3aa11c53cf344ea069db95cecb81ad7453c8f276b2a1062979611f09c", "logIndex": "0x4", "removed": false}, {"address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", "topics": ["0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65", "0x0000000000000000000000001111111254fb6c44bac0bed2854e76f90643097d"], "data": "0x00000000000000000000000000000000000000000000000011f8b9803bc57124", "blockNumber": "0xe147ed", "transactionHash": "0x163dae461ab32787eaecdad0748c9cf5fe0a22b443bc694efae9b80e319d9559", "transactionIndex": "0x0", "blockHash": "0x720704f3aa11c53cf344ea069db95cecb81ad7453c8f276b2a1062979611f09c", "logIndex": "0x5", "removed": false}, {"address": "0x881d40237659c251811cec9c364ef91dc08d300c", "topics": ["0xbeee1e6e7fe307ddcf84b0a16137a4430ad5e2480fc4f4a8e250ab56ccd7630d", "0xbd5c436f8c83379009c1962310b8347e561d1900906d3fe4075b1596f8955f88", "0x000000000000000000000000dd19b32a084be0a318f11edb3f7034889c03c51f"], "data": "0x", "blockNumber": "0xe147ed", "transactionHash": "0x163dae461ab32787eaecdad0748c9cf5fe0a22b443bc694efae9b80e319d9559", "transactionIndex": "0x0", "blockHash": "0x720704f3aa11c53cf344ea069db95cecb81ad7453c8f276b2a1062979611f09c", "logIndex": "0x6", "removed": false}], "logsBloom": "0x00200000000000001000000080000000000000000000010000000000000000000000010000000000000090000001010002000000080008000000000000000000000000000000000000020008000000200000000000400000000004000000400000000000000000000000000000000000000000000000040000000010000000000000010000001100000000000000008000000000000000080020004000100000000000000000000000000080000000000000000000000000000000000000000001000002000000100004000000000000000000000000001000000002000000000024200000000000000000000000000000000000004000000000000000001000", "status": "0x1", "to": "0x881d40237659c251811cec9c364ef91dc08d300c", "transactionHash": "0x163dae461ab32787eaecdad0748c9cf5fe0a22b443bc694efae9b80e319d9559", "transactionIndex": "0x0", "type": "0x2"});
        let receipt: Receipt = serde_json::from_value(response).unwrap();
        assert_eq!(
            receipt.cumulative_gas_used,
            U256::from_str_radix("189807", 10).unwrap()
        );
    }

    #[test_log::test]
    fn receipts_batch() {
        // this block (15573637) was chosen since it contains all tx types (legacy, access list,
        // eip1559) as well as contract creation txs
        let expected: String =
            std::fs::read_to_string("../test_assets/geth_batch/receipts.json").unwrap();
        let receipts: Receipts = serde_json::from_str(&expected).unwrap();
        let expected_receipts_root: B256 = B256::from_slice(
            &hex_decode("0xc9e543effd8c9708acc53249157c54b0c6aecd69285044bcb9df91cedc6437ad")
                .unwrap(),
        );
        assert_eq!(receipts.root().unwrap(), expected_receipts_root);
    }

    #[test_log::test]
    fn pre_byzantium_receipts_batch() {
        // batched group of pre-byzantium receipts, containing the "root" field instead of "status"
        // sourced from infura.
        let expected: String =
            std::fs::read_to_string("../test_assets/infura_batch/receipts-1114271.json").unwrap();
        let receipts: Receipts = serde_json::from_str(&expected).unwrap();
        let expected_receipts_root: B256 = B256::from_slice(
            &hex_decode("0xd262fe545cec9ec04f4246334d05437fac8d8dfe201a1f6476fab545878cb251")
                .unwrap(),
        );
        assert_eq!(receipts.root().unwrap(), expected_receipts_root);
    }

    #[rstest::rstest]
    // without blob txs
    #[case(
        "19433902",
        "0xe83c57ae3bcb0945878a6880421f617200a17d00656a1f0c681380cfc4a46a09"
    )]
    // with blob txs
    #[case(
        "19433903",
        "0x6c7e4d6a0eadb934d2ca845f11f6aa81c5fdec53310048e8cd0b3f33d06f46d8"
    )]
    fn dencun_receipts(#[case] block_number: &str, #[case] expected_root: &str) {
        let receipts = std::fs::read_to_string(format!(
            "../test_assets/infura_batch/receipts-{block_number}.json"
        ))
        .unwrap();
        let receipts: Receipts = serde_json::from_str(&receipts).unwrap();
        let expected_receipts_root: B256 = B256::from_str(expected_root).unwrap();
        assert_eq!(receipts.root().unwrap(), expected_receipts_root);
    }

    const EXPECTED_RECEIPTS_ROOT: &str =
        "0x168a3827607627e781941dc777737fc4b6beb69a8b139240b881992b35b854ea";
    const RECEIPT_0: &str = "0x02f90554018302e56fb9010000200000000000001000000080000000000000000000010000000000000000000000010000000000000090000001010002000000080008000000000000000000000000000000000000020008000000200000000000400000000004000000400000000000000000000000000000000000000000000000040000000010000000000000010000001100000000000000008000000000000000080020004000100000000000000000000000000080000000000000000000000000000000000000000001000002000000100004000000000000000000000000001000000002000000000024200000000000000000000000000000000000004000000000000000001000f90449f89b94dac17f958d2ee523a2206206994597c13d831ec7f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000dd19b32a084be0a318f11edb3f7034889c03c51fa000000000000000000000000074de5d4fcbf63e00296fd95d33236b9794016631a000000000000000000000000000000000000000000000000000000000979aedebf89b94dac17f958d2ee523a2206206994597c13d831ec7f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa000000000000000000000000074de5d4fcbf63e00296fd95d33236b9794016631a000000000000000000000000074c99f3f5331676f6aec2756e1f39b4fc029a83ea000000000000000000000000000000000000000000000000000000000979aedebf89b94c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa000000000000000000000000074c99f3f5331676f6aec2756e1f39b4fc029a83ea00000000000000000000000001111111254fb6c44bac0bed2854e76f90643097da000000000000000000000000000000000000000000000000011f8b9803bc57124f8799474c99f3f5331676f6aec2756e1f39b4fc029a83ee1a01c411e9a96e071241c2f21f7726b17ae89e3cab4c78be50e062b03a9fffbbad1b8400000000000000000000000000000000000000000000000657acd23da825d7df70000000000000000000000000000000000000000000000000000035616e4172af8fc9474c99f3f5331676f6aec2756e1f39b4fc029a83ef863a0d78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822a00000000000000000000000001111111254fb6c44bac0bed2854e76f90643097da00000000000000000000000001111111254fb6c44bac0bed2854e76f90643097db880000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000979aedeb00000000000000000000000000000000000000000000000011f8b9803bc571240000000000000000000000000000000000000000000000000000000000000000f87a94c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f842a07fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65a00000000000000000000000001111111254fb6c44bac0bed2854e76f90643097da000000000000000000000000000000000000000000000000011f8b9803bc57124f87b94881d40237659c251811cec9c364ef91dc08d300cf863a0beee1e6e7fe307ddcf84b0a16137a4430ad5e2480fc4f4a8e250ab56ccd7630da0bd5c436f8c83379009c1962310b8347e561d1900906d3fe4075b1596f8955f88a0000000000000000000000000dd19b32a084be0a318f11edb3f7034889c03c51f80";
    const RECEIPT_1: &str = "0x02f901860183035291b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000080000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000400000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000400000000000000000f87cf87a94c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f842a0e1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109ca000000000000000000000000032e3d029328bd3e22adf7c8cda99a96931faf2a4a00000000000000000000000000000000000000000000000000e92596fd6290000";
    const RECEIPT_2: &str = "0x02f901a70183040868b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000010000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000100000400000000000000000000000000000000020000000000000002000000080000000000000000000000000000000000000000020000000000400000000000000000000000000000000000000000000000000010000000004000000000000000000000000000000000000000000000000000f89df89b9495ad61b0a150d79219dcf64e1e6cc01f0b64c4cef863a08c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925a0000000000000000000000000ed6021c55398a3690c2ac3ae45c65decbd36c83da0000000000000000000000000881d40237659c251811cec9c364ef91dc08d300ca0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const RECEIPT_3: &str = "0x02f9071001830718a1b9010000000000000000001000000000080000000000000004000000000000000000000000010000000000000010000000000000008000000008000000000000200000000000000000002008020008000050000000000000000000200004000000000000000000000000000004000000000040000000000010000000000010000000000000000000000000000400000100000400000000010000000020000008000000028000000000200002004000080000000000000000000000200002000000004001020002000000400000000000000000000000000000000000000008000000000030000008004000000000000000000000000000000000000000000000001000f90605f89b9495ad61b0a150d79219dcf64e1e6cc01f0b64c4cef863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000ed6021c55398a3690c2ac3ae45c65decbd36c83da000000000000000000000000074de5d4fcbf63e00296fd95d33236b9794016631a0000000000000000000000000000000000000000000fe30137375b8c39c8a5557f89b9495ad61b0a150d79219dcf64e1e6cc01f0b64c4cef863a08c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925a0000000000000000000000000ed6021c55398a3690c2ac3ae45c65decbd36c83da0000000000000000000000000881d40237659c251811cec9c364ef91dc08d300ca0ffffffffffffffffffffffffffffffffffffffffff01cfec8c8a473c6375aaa8f89b9495ad61b0a150d79219dcf64e1e6cc01f0b64c4cef863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa000000000000000000000000074de5d4fcbf63e00296fd95d33236b9794016631a000000000000000000000000056178a0d5f301baf6cf3e1cd53d9863437345bf9a0000000000000000000000000000000000000000000fe30137375b8c39c8a5557f89b9495ad61b0a150d79219dcf64e1e6cc01f0b64c4cef863a08c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925a000000000000000000000000074de5d4fcbf63e00296fd95d33236b9794016631a0000000000000000000000000def1c0ded9bec7f1a1670819833240f027b25effa0ffffffffffffffffffffffffffffffffffffffe854fa36ae7edbec08c268da35f89b94a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa000000000000000000000000056178a0d5f301baf6cf3e1cd53d9863437345bf9a000000000000000000000000074de5d4fcbf63e00296fd95d33236b9794016631a000000000000000000000000000000000000000000000000000000000c7a17304f9013a94def1c0ded9bec7f1a1670819833240f027b25effe1a0829fa99d94dc4636925b38632e625736a614c154d55006b7ab6bea979c210c32b901001a4747f0f002cf6a1e76879e0a2a28cb1aebe5ff936d0b534d7d8d23e380467500000000000000000000000056178a0d5f301baf6cf3e1cd53d9863437345bf900000000000000000000000074de5d4fcbf63e00296fd95d33236b9794016631000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000095ad61b0a150d79219dcf64e1e6cc01f0b64c4ce000000000000000000000000000000000000000000fe30137375b8c39c8a555700000000000000000000000000000000000000000000000000000000c7a173040000000000000000000000000000000000000000000000000000000000000000f89b94a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa000000000000000000000000074de5d4fcbf63e00296fd95d33236b9794016631a00000000000000000000000002acf35c9a3f4c5c3f4c78ef5fb64c3ee82f07c45a00000000000000000000000000000000000000000000000000000000001bf2c34f89b94a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa000000000000000000000000074de5d4fcbf63e00296fd95d33236b9794016631a0000000000000000000000000ed6021c55398a3690c2ac3ae45c65decbd36c83da000000000000000000000000000000000000000000000000000000000c5e246d0f87b94881d40237659c251811cec9c364ef91dc08d300cf863a0beee1e6e7fe307ddcf84b0a16137a4430ad5e2480fc4f4a8e250ab56ccd7630da0a8dc30b66c6d4a8aac3d15925bfca09e42cac4a00c50f9949154b045088e2ac2a0000000000000000000000000ed6021c55398a3690c2ac3ae45c65decbd36c83d80";
    const RECEIPT_4: &str = "0x02f901098083076f7eb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0";
    const RECEIPT_5: &str = "0x02f90109808308851fb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0";
    const RECEIPT_6: &str = "0xf90109018308d727b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0";
    const RECEIPT_7: &str = "0xf901a70183098b44b9010000000000000000000000000000000000000000010000000001000000000000000000000000000000000000000000010000000000000000040000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000080000000000000000000000000000000000100000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000f89df89b94dac17f958d2ee523a2206206994597c13d831ec7f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa00000000000000000000000008b8a4abc707f16da24b795e3e46ed22975a9d329a000000000000000000000000088bd4648737098aa9096bfba765dec014d2a11c1a00000000000000000000000000000000000000000000000000000000010ea71c0";
    const RECEIPT_8: &str = "0xf901a701830a8215b9010000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000010000000000000000040000000000000000000000000000000000000008000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000080000000000000000000000000000000000100800000000002000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000f89df89b94dac17f958d2ee523a2206206994597c13d831ec7f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa00000000000000000000000008b8a4abc707f16da24b795e3e46ed22975a9d329a00000000000000000000000000f893a99b0165d3c92bc7d578afbc2104500761aa0000000000000000000000000000000000000000000000000000000002f71ff00";
    const RECEIPT_9: &str = "0x02f901a701830b2cdbb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000010000000080000000000000000000000200008000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000080000000000000000000000020000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000f89df89b94dac17f958d2ee523a2206206994597c13d831ec7f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000b24abf582bab677c3bc8aa60706d212284a35b51a00000000000000000000000007abe0ce388281d2acf297cb089caef3819b13448a00000000000000000000000000000000000000000000000000000002fcc3cce80";
    const RECEIPT_10: &str = "0x02f9010901830b7ee3b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0";
    const RECEIPT_11: &str = "0x02f9010901830bd0ebb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0";
    const RECEIPT_12: &str = "0x02f9058401830e7c79b9010000000000000000000000000000000000000000000000000000000000000000002000100000000000000000020000000000000000000200000000000000000000000000000000000000000001002000000000000001000000000000000000000000000000020800000000000000000800000010000000000000000000000000000000000000000000000000000000000000400480000000000000000040000000000000001000000000000000000000000000000000000000000000000000000008000000000000000000000000000000004000000000000000000000000020000000000000000000000200000000000000000000000000000000010000000000f90479f9033c945edd5f803b831b47715ad3e11a90dd244f0cd0a9f842a0f6a97944f31ea060dfde0566e4167c1a1082551e64b60ecb14d599a9d023d451a00000000000000000000000000000000000000000000000000000000000000af6b902e00000000000000000000000000000000000000000000000000000000002740989000000000000000000000000f6e7dba31369024f0044f24ce5dc2c612b298edd00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000002a00000000000000000000000723b92452ba80acd1bfd31e98693a5110001249e01000000000000000000000000000000000000000000000000000000000000000f00000000000000000000000000000000000000000000000000000000025d005000000000000000000000000000000000000000000000000000000000025eb3a800000000000000000000000000000000000000000000000000000000025f4e9d0000000000000000000000000000000000000000000000000000000002616fa00000000000000000000000000000000000000000000000000000000002662a9000000000000000000000000000000000000000000000000000000000026dcbb000000000000000000000000000000000000000000000000000000000027409890000000000000000000000000000000000000000000000000000000002740989000000000000000000000000000000000000000000000000000000000274098900000000000000000000000000000000000000000000000000000000027621e400000000000000000000000000000000000000000000000000000000027621e400000000000000000000000000000000000000000000000000000000027621e400000000000000000000000000000000000000000000000000000000027818c00000000000000000000000000000000000000000000000000000000002920c5a0000000000000000000000000000000000000000000000000000000002920c5a000000000000000000000000000000000000000000000000000000000000000f0408000b05020c070f090a0106030e0000000000000000000000000000000000f89b945edd5f803b831b47715ad3e11a90dd244f0cd0a9f863a00109fc6f55cf40689f02fbaad7af7fe7bbac8a3d2186600afc7d3e10cac60271a00000000000000000000000000000000000000000000000000000000000000af6a00000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000627d9afaf89b945edd5f803b831b47715ad3e11a90dd244f0cd0a9f863a00559884fd3a460db3073b7fc896cc77986f16e378210ded43186175bf646fc5fa00000000000000000000000000000000000000000000000000000000002740989a00000000000000000000000000000000000000000000000000000000000000af6a000000000000000000000000000000000000000000000000000000000627d9afa";
    const RECEIPT_13: &str = "0x02f901a701830f3a12b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000108000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000100000000000000000000000000010000000000000000000020000000000000200000000000000001000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001f89df89b94a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa000000000000000000000000021a31ee1afc51d94c2efccaa2092ad1028285549a0000000000000000000000000f841a830cd94f6f00be674c81f57d5fcbbee2857a0000000000000000000000000000000000000000000000000000000038869ffb0";
    const RECEIPT_14: &str = "0x02f901a70183103a6bb9010000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000008000000000000000000000000000000000000000000000000000000000000000000000000200000000000000040000010000000000000000000000000000000000000000040000000010000000000000000000000000000000000200000000000000000000000000000000000000008000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000f89df89b94a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000503828976d22510aad0201ac7ec88293211d23daa00000000000000000000000008954b57277a9d7260bb5535afa83d53bf343637ca0000000000000000000000000000000000000000000000000000000001e742c50";
    const RECEIPT_15: &str = "0x02f901a70183113154b9010000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000010400000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000002000000000000000000000000000000100000000000000080000000000080000000000000000000000000000001000000000000000002000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000f89df89b94dac17f958d2ee523a2206206994597c13d831ec7f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000dfd5293d8e347dfe59e90efd55b2956a1343963da00000000000000000000000004bb8adce5e7297f2d8c5a2302a68d65eb44158cda0000000000000000000000000000000000000000000000000000000000d41fae9";
    const RECEIPT_16: &str = "0x02f901a7018312e726b9010000000000400000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000008000000000000000000000200000000000000000000000000000000000000000000000000200000000000000040000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000802000000002000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000f89df89b9488df592f8eb5d7bd38bfef7deb0fbc02cf3778a0f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000503828976d22510aad0201ac7ec88293211d23daa00000000000000000000000004b7575ef97285f846c944eee2e155bd3ceb65343a0000000000000000000000000000000000000000000000025e320a2817417f400";
    const RECEIPT_17: &str = "0x02f90109018313bba9b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0";
    const RECEIPT_18: &str = "0x02f901090183140db1b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0";
}
