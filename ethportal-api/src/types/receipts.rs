use crate::types::{block_body::TransactionId, log::TransactionLog};
use eth_trie::{EthTrie, MemoryDB, Trie, TrieError};
use ethereum_types::{Bloom, H256, U256};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use ssz::{Decode, Encode};
use ssz_types::{typenum, VariableList};
use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

// 2 ^ 14
const MAX_TRANSACTION_COUNT: usize = 16384;

/// Represents the `Receipts` content type used by portal history network
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockReceipts {
    pub receipt_list: Vec<Receipt>,
}

impl BlockReceipts {
    pub fn root(&self) -> Result<H256, TrieError> {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb);

        // Insert receipts into receipts tree
        for (index, receipt) in self.receipt_list.iter().enumerate() {
            let path = rlp::encode(&index).freeze().to_vec();
            let encoded_receipt = receipt.encode();
            trie.insert(&path, &encoded_receipt)?;
        }

        trie.root_hash()
    }
}

impl Encode for BlockReceipts {
    // note: MAX_LENGTH attributes (defined in portal history spec) are not currently enforced
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let encoded_receipts: Vec<Vec<u8>> = self
            .receipt_list
            .iter()
            .map(|receipt| receipt.encode())
            .collect();

        // 2 ^ 14 MAX_TRANSACTION_COUNT = 16384
        let encoded_receipts: VariableList<_, typenum::U16384> =
            VariableList::from(encoded_receipts);

        encoded_receipts.ssz_append(buf)
    }

    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

impl Decode for BlockReceipts {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let encoded_receipts: Vec<Vec<u8>> =
            ssz::decode_list_of_variable_length_items(bytes, Some(MAX_TRANSACTION_COUNT))?;

        let receipt_list: Vec<Receipt> = encoded_receipts
            .iter()
            .map(|bytes| Receipt::decode(bytes).unwrap())
            .collect();

        Ok(Self { receipt_list })
    }
}

impl Serialize for BlockReceipts {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let ssz_receipts = self.as_ssz_bytes();
        serializer.serialize_str(&format!("0x{}", hex::encode(ssz_receipts)))
    }
}

impl<'de> Deserialize<'de> for BlockReceipts {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let receipts = BlockReceipts::from_ssz_bytes(
            &hex::decode(s.strip_prefix("0x").unwrap_or(&s)).map_err(de::Error::custom)?,
        )
        .map_err(|_| de::Error::custom("Unable to ssz decode Receipts bytes"))?;

        Ok(receipts)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Receipt {
    Legacy(TransactionReceipt),
    AccessList(TransactionReceipt),
    EIP1559(TransactionReceipt),
}

impl Receipt {
    /// Create a new receipt.
    pub fn new(type_id: TransactionId, transaction_receipt: TransactionReceipt) -> Self {
        // currently we are using same receipt for both legacy and typed transaction
        match type_id {
            TransactionId::EIP1559 => Self::EIP1559(transaction_receipt),
            TransactionId::AccessList => Self::AccessList(transaction_receipt),
            TransactionId::Legacy => Self::Legacy(transaction_receipt),
        }
    }

    pub fn receipt(&self) -> &TransactionReceipt {
        match self {
            Self::Legacy(receipt) => receipt,
            Self::AccessList(receipt) => receipt,
            Self::EIP1559(receipt) => receipt,
        }
    }

    pub fn receipt_mut(&mut self) -> &mut TransactionReceipt {
        match self {
            Self::Legacy(receipt) => receipt,
            Self::AccessList(receipt) => receipt,
            Self::EIP1559(receipt) => receipt,
        }
    }
    fn encode(&self) -> Vec<u8> {
        let mut stream = RlpStream::new();
        match self {
            Self::Legacy(receipt) => {
                receipt.rlp_append(&mut stream);
                stream.out().freeze().to_vec()
            }
            Self::AccessList(receipt) => {
                receipt.rlp_append(&mut stream);
                [&[TransactionId::AccessList as u8], stream.as_raw()].concat()
            }
            Self::EIP1559(receipt) => {
                receipt.rlp_append(&mut stream);
                [&[TransactionId::EIP1559 as u8], stream.as_raw()].concat()
            }
        }
    }

    #[allow(dead_code)]
    fn decode(receipt: &[u8]) -> Result<Self, DecoderError> {
        // at least one byte needs to be present
        if receipt.is_empty() {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        let id = TransactionId::try_from(receipt[0])
            .map_err(|_| DecoderError::Custom("Unknown transaction id"))?;
        //other transaction types
        match id {
            TransactionId::EIP1559 => Ok(Self::EIP1559(rlp::decode(&receipt[1..])?)),
            TransactionId::AccessList => Ok(Self::AccessList(rlp::decode(&receipt[1..])?)),
            TransactionId::Legacy => Ok(Self::Legacy(rlp::decode(receipt)?)),
        }
    }
}

impl Deref for Receipt {
    type Target = TransactionReceipt;

    fn deref(&self) -> &Self::Target {
        self.receipt()
    }
}

impl DerefMut for Receipt {
    fn deref_mut(&mut self) -> &mut TransactionReceipt {
        self.receipt_mut()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TransactionOutcome {
    /// State root is known, before EIP-658 is enabled.
    StateRoot(H256),
    /// Status code is known. EIP-658 rules.
    StatusCode(u8),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionReceipt {
    pub cumulative_gas_used: U256,
    pub log_bloom: Bloom,
    pub logs: Vec<TransactionLog>,
    pub outcome: TransactionOutcome,
}

impl TransactionReceipt {
    pub fn new(
        outcome: TransactionOutcome,
        cumulative_gas_used: U256,
        logs: Vec<TransactionLog>,
    ) -> Self {
        TransactionReceipt {
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

impl Decodable for TransactionReceipt {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        match rlp.item_count()? {
            4 => Ok(TransactionReceipt {
                cumulative_gas_used: rlp.val_at(1)?,
                log_bloom: rlp.val_at(2)?,
                logs: rlp.list_at(3)?,
                outcome: {
                    let first = rlp.at(0)?;
                    if first.is_data() && first.data()?.len() <= 1 {
                        TransactionOutcome::StatusCode(first.as_val()?)
                    } else {
                        TransactionOutcome::StateRoot(first.as_val()?)
                    }
                },
            }),
            _ => Err(DecoderError::RlpIncorrectListLen),
        }
    }
}

impl Encodable for TransactionReceipt {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4);
        match self.outcome {
            TransactionOutcome::StateRoot(ref root) => {
                s.append(root);
            }
            TransactionOutcome::StatusCode(ref status_code) => {
                s.append(status_code);
            }
        }
        s.append(&self.cumulative_gas_used);
        s.append(&self.log_bloom);
        s.append_list(&self.logs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::bytes::Bytes;
    use ethereum_types::H160;
    use serde_json::json;
    use std::str::FromStr;

    #[test]
    fn legacy_receipt_encode_decode() {
        let receipt_rlp = hex::decode(RECEIPT_6).unwrap();
        let receipt = Receipt::decode(&receipt_rlp).expect("error decoding receipt");
        // tx link: https://etherscan.io/tx/0x147c84ddb366ae572ce5aa4d815e62de3a151133479fbb414e25d32bd7db9aa5
        assert_eq!(receipt.cumulative_gas_used, U256::from(579367));
        assert_eq!(receipt.logs, []);
        assert_eq!(receipt.outcome, TransactionOutcome::StatusCode(1));
        let encoded = receipt.encode();
        assert_eq!(encoded, receipt_rlp);
    }

    #[test]
    fn typed_receipt_encode_decode() {
        let receipt_rlp = hex::decode(RECEIPT_0).unwrap();
        let receipt = Receipt::decode(&receipt_rlp).expect("error decoding receipt");
        // tx link: https://etherscan.io/tx/0x163dae461ab32787eaecdad0748c9cf5fe0a22b443bc694efae9b80e319d9559
        assert_eq!(receipt.cumulative_gas_used, U256::from(189807));
        assert_eq!(receipt.logs.len(), 7);
        assert_eq!(receipt.outcome, TransactionOutcome::StatusCode(1));
        let encoded = receipt.encode();
        assert_eq!(encoded, receipt_rlp);
    }

    #[test]
    fn cumulative_gas_used() {
        // cumulative gas for last tx in block should match block's gas used
        let receipt_rlp = hex::decode(RECEIPT_18).unwrap();
        let receipt = Receipt::decode(&receipt_rlp).expect("error decoding receipt");
        // https://etherscan.io/block/14764013
        assert_eq!(receipt.cumulative_gas_used, U256::from(1314225));
    }

    #[test]
    fn calculate_receipts_root() {
        let receipts = BlockReceipts {
            receipt_list: vec![
                Receipt::decode(&hex::decode(RECEIPT_0).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_1).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_2).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_3).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_4).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_5).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_6).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_7).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_8).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_9).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_10).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_11).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_12).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_13).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_14).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_15).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_16).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_17).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_18).unwrap()).unwrap(),
            ],
        };
        assert_eq!(
            hex::encode(receipts.root().unwrap()),
            EXPECTED_RECEIPTS_ROOT.to_owned()
        );
    }

    #[test]
    fn ssz_encode_decode_receipts() {
        let receipts = BlockReceipts {
            receipt_list: vec![
                Receipt::decode(&hex::decode(RECEIPT_0).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_1).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_2).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_3).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_4).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_5).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_6).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_7).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_8).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_9).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_10).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_11).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_12).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_13).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_14).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_15).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_16).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_17).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_18).unwrap()).unwrap(),
            ],
        };
        let encoded = receipts.as_ssz_bytes();

        let expected: Vec<u8> = std::fs::read("./src/assets/test/receipts_14764013.bin").unwrap();
        assert_eq!(hex::encode(&encoded), hex::encode(expected));

        let decoded = BlockReceipts::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(receipts, decoded);
    }

    #[test]
    fn receipts_ser_de() {
        let receipts = BlockReceipts {
            receipt_list: vec![
                Receipt::decode(&hex::decode(RECEIPT_0).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_1).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_2).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_3).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_4).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_5).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_6).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_7).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_8).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_9).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_10).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_11).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_12).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_13).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_14).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_15).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_16).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_17).unwrap()).unwrap(),
                Receipt::decode(&hex::decode(RECEIPT_18).unwrap()).unwrap(),
            ],
        };

        let receipts_json = json!(format!("0x{}", hex::encode(receipts.as_ssz_bytes())));

        let receipts: BlockReceipts = serde_json::from_value(receipts_json.clone()).unwrap();

        assert_eq!(
            serde_json::to_string(&receipts_json).unwrap(),
            serde_json::to_string(&receipts).unwrap()
        )
    }

    // OpenEthereum Tests
    // https://github.com/openethereum/openethereum/blob/main/crates/ethcore/types/src/receipt.rs

    #[test]
    fn no_state_root() {
        let expected = hex::decode("f90162a02f697d671e9ae4ee24a43c4b0d7e15f1cb4ba6de1561120d43b9a4e8c4a8a6ee83040caeb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000f838f794dcf421d093428b096ca501a7cd1a740855a7976fc0a00000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let receipt = Receipt::new(
            TransactionId::Legacy,
            TransactionReceipt::new(
                TransactionOutcome::StateRoot(
                    H256::from_str(
                        "2f697d671e9ae4ee24a43c4b0d7e15f1cb4ba6de1561120d43b9a4e8c4a8a6ee",
                    )
                    .unwrap(),
                ),
                U256::from_str_radix("40cae", 16).unwrap(),
                vec![TransactionLog {
                    address: H160::from_str("dcf421d093428b096ca501a7cd1a740855a7976f").unwrap(),
                    topics: vec![],
                    data: Bytes::from(vec![0u8; 32]),
                }],
            ),
        );
        let encoded = receipt.encode();
        assert_eq!(encoded, expected);
        let decoded = Receipt::decode(&encoded).expect("decoding receipt failed");
        assert_eq!(decoded, receipt);
    }

    #[test]
    fn basic_legacy() {
        let expected = hex::decode("f90162a02f697d671e9ae4ee24a43c4b0d7e15f1cb4ba6de1561120d43b9a4e8c4a8a6ee83040caeb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000f838f794dcf421d093428b096ca501a7cd1a740855a7976fc0a00000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let receipt = Receipt::new(
            TransactionId::Legacy,
            TransactionReceipt::new(
                TransactionOutcome::StateRoot(
                    H256::from_str(
                        "2f697d671e9ae4ee24a43c4b0d7e15f1cb4ba6de1561120d43b9a4e8c4a8a6ee",
                    )
                    .unwrap(),
                ),
                U256::from_str_radix("40cae", 16).unwrap(),
                vec![TransactionLog {
                    address: H160::from_str("dcf421d093428b096ca501a7cd1a740855a7976f").unwrap(),
                    topics: vec![],
                    data: Bytes::from(vec![0u8; 32]),
                }],
            ),
        );
        let encoded = receipt.encode();
        assert_eq!(encoded, expected);
        let decoded = Receipt::decode(&encoded).expect("decoding receipt failed");
        assert_eq!(decoded, receipt);
    }

    #[test]
    fn basic_access_list() {
        let expected = hex::decode("01f90162a02f697d671e9ae4ee24a43c4b0d7e15f1cb4ba6de1561120d43b9a4e8c4a8a6ee83040caeb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000f838f794dcf421d093428b096ca501a7cd1a740855a7976fc0a00000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let receipt = Receipt::new(
            TransactionId::AccessList,
            TransactionReceipt::new(
                TransactionOutcome::StateRoot(
                    H256::from_str(
                        "2f697d671e9ae4ee24a43c4b0d7e15f1cb4ba6de1561120d43b9a4e8c4a8a6ee",
                    )
                    .unwrap(),
                ),
                U256::from_str_radix("40cae", 16).unwrap(),
                vec![TransactionLog {
                    address: H160::from_str("dcf421d093428b096ca501a7cd1a740855a7976f").unwrap(),
                    topics: vec![],
                    data: Bytes::from(vec![0u8; 32]),
                }],
            ),
        );
        let encoded = receipt.encode();
        assert_eq!(&encoded, &expected);
        let decoded = Receipt::decode(&encoded).expect("decoding receipt failed");
        assert_eq!(decoded, receipt);
    }

    #[test]
    fn basic_eip1559() {
        let expected = hex::decode("02f90162a02f697d671e9ae4ee24a43c4b0d7e15f1cb4ba6de1561120d43b9a4e8c4a8a6ee83040caeb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000f838f794dcf421d093428b096ca501a7cd1a740855a7976fc0a00000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let receipt = Receipt::new(
            TransactionId::EIP1559,
            TransactionReceipt::new(
                TransactionOutcome::StateRoot(
                    H256::from_str(
                        "2f697d671e9ae4ee24a43c4b0d7e15f1cb4ba6de1561120d43b9a4e8c4a8a6ee",
                    )
                    .unwrap(),
                ),
                U256::from_str_radix("40cae", 16).unwrap(),
                vec![TransactionLog {
                    address: H160::from_str("dcf421d093428b096ca501a7cd1a740855a7976f").unwrap(),
                    topics: vec![],
                    data: Bytes::from(vec![0u8; 32]),
                }],
            ),
        );
        let encoded = receipt.encode();
        assert_eq!(&encoded, &expected);
        let decoded = Receipt::decode(&encoded).expect("decoding receipt failed");
        assert_eq!(decoded, receipt);
    }

    #[test]
    fn status_code() {
        let expected = hex::decode("f901428083040caeb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000f838f794dcf421d093428b096ca501a7cd1a740855a7976fc0a00000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let receipt = Receipt::new(
            TransactionId::Legacy,
            TransactionReceipt::new(
                TransactionOutcome::StatusCode(0),
                U256::from_str_radix("40cae", 16).unwrap(),
                vec![TransactionLog {
                    address: H160::from_str("dcf421d093428b096ca501a7cd1a740855a7976f").unwrap(),
                    topics: vec![],
                    data: Bytes::from(vec![0u8; 32]),
                }],
            ),
        );
        let encoded = receipt.encode();
        assert_eq!(&encoded[..], &expected[..]);
        let decoded = Receipt::decode(&encoded).expect("decoding receipt failed");
        assert_eq!(decoded, receipt);
    }

    const EXPECTED_RECEIPTS_ROOT: &str =
        "168a3827607627e781941dc777737fc4b6beb69a8b139240b881992b35b854ea";
    const RECEIPT_0: &str = "02f90554018302e56fb9010000200000000000001000000080000000000000000000010000000000000000000000010000000000000090000001010002000000080008000000000000000000000000000000000000020008000000200000000000400000000004000000400000000000000000000000000000000000000000000000040000000010000000000000010000001100000000000000008000000000000000080020004000100000000000000000000000000080000000000000000000000000000000000000000001000002000000100004000000000000000000000000001000000002000000000024200000000000000000000000000000000000004000000000000000001000f90449f89b94dac17f958d2ee523a2206206994597c13d831ec7f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000dd19b32a084be0a318f11edb3f7034889c03c51fa000000000000000000000000074de5d4fcbf63e00296fd95d33236b9794016631a000000000000000000000000000000000000000000000000000000000979aedebf89b94dac17f958d2ee523a2206206994597c13d831ec7f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa000000000000000000000000074de5d4fcbf63e00296fd95d33236b9794016631a000000000000000000000000074c99f3f5331676f6aec2756e1f39b4fc029a83ea000000000000000000000000000000000000000000000000000000000979aedebf89b94c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa000000000000000000000000074c99f3f5331676f6aec2756e1f39b4fc029a83ea00000000000000000000000001111111254fb6c44bac0bed2854e76f90643097da000000000000000000000000000000000000000000000000011f8b9803bc57124f8799474c99f3f5331676f6aec2756e1f39b4fc029a83ee1a01c411e9a96e071241c2f21f7726b17ae89e3cab4c78be50e062b03a9fffbbad1b8400000000000000000000000000000000000000000000000657acd23da825d7df70000000000000000000000000000000000000000000000000000035616e4172af8fc9474c99f3f5331676f6aec2756e1f39b4fc029a83ef863a0d78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822a00000000000000000000000001111111254fb6c44bac0bed2854e76f90643097da00000000000000000000000001111111254fb6c44bac0bed2854e76f90643097db880000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000979aedeb00000000000000000000000000000000000000000000000011f8b9803bc571240000000000000000000000000000000000000000000000000000000000000000f87a94c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f842a07fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65a00000000000000000000000001111111254fb6c44bac0bed2854e76f90643097da000000000000000000000000000000000000000000000000011f8b9803bc57124f87b94881d40237659c251811cec9c364ef91dc08d300cf863a0beee1e6e7fe307ddcf84b0a16137a4430ad5e2480fc4f4a8e250ab56ccd7630da0bd5c436f8c83379009c1962310b8347e561d1900906d3fe4075b1596f8955f88a0000000000000000000000000dd19b32a084be0a318f11edb3f7034889c03c51f80";
    const RECEIPT_1: &str = "02f901860183035291b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000080000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000400000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000400000000000000000f87cf87a94c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f842a0e1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109ca000000000000000000000000032e3d029328bd3e22adf7c8cda99a96931faf2a4a00000000000000000000000000000000000000000000000000e92596fd6290000";
    const RECEIPT_2: &str = "02f901a70183040868b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000010000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000100000400000000000000000000000000000000020000000000000002000000080000000000000000000000000000000000000000020000000000400000000000000000000000000000000000000000000000000010000000004000000000000000000000000000000000000000000000000000f89df89b9495ad61b0a150d79219dcf64e1e6cc01f0b64c4cef863a08c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925a0000000000000000000000000ed6021c55398a3690c2ac3ae45c65decbd36c83da0000000000000000000000000881d40237659c251811cec9c364ef91dc08d300ca0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const RECEIPT_3: &str = "02f9071001830718a1b9010000000000000000001000000000080000000000000004000000000000000000000000010000000000000010000000000000008000000008000000000000200000000000000000002008020008000050000000000000000000200004000000000000000000000000000004000000000040000000000010000000000010000000000000000000000000000400000100000400000000010000000020000008000000028000000000200002004000080000000000000000000000200002000000004001020002000000400000000000000000000000000000000000000008000000000030000008004000000000000000000000000000000000000000000000001000f90605f89b9495ad61b0a150d79219dcf64e1e6cc01f0b64c4cef863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000ed6021c55398a3690c2ac3ae45c65decbd36c83da000000000000000000000000074de5d4fcbf63e00296fd95d33236b9794016631a0000000000000000000000000000000000000000000fe30137375b8c39c8a5557f89b9495ad61b0a150d79219dcf64e1e6cc01f0b64c4cef863a08c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925a0000000000000000000000000ed6021c55398a3690c2ac3ae45c65decbd36c83da0000000000000000000000000881d40237659c251811cec9c364ef91dc08d300ca0ffffffffffffffffffffffffffffffffffffffffff01cfec8c8a473c6375aaa8f89b9495ad61b0a150d79219dcf64e1e6cc01f0b64c4cef863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa000000000000000000000000074de5d4fcbf63e00296fd95d33236b9794016631a000000000000000000000000056178a0d5f301baf6cf3e1cd53d9863437345bf9a0000000000000000000000000000000000000000000fe30137375b8c39c8a5557f89b9495ad61b0a150d79219dcf64e1e6cc01f0b64c4cef863a08c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925a000000000000000000000000074de5d4fcbf63e00296fd95d33236b9794016631a0000000000000000000000000def1c0ded9bec7f1a1670819833240f027b25effa0ffffffffffffffffffffffffffffffffffffffe854fa36ae7edbec08c268da35f89b94a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa000000000000000000000000056178a0d5f301baf6cf3e1cd53d9863437345bf9a000000000000000000000000074de5d4fcbf63e00296fd95d33236b9794016631a000000000000000000000000000000000000000000000000000000000c7a17304f9013a94def1c0ded9bec7f1a1670819833240f027b25effe1a0829fa99d94dc4636925b38632e625736a614c154d55006b7ab6bea979c210c32b901001a4747f0f002cf6a1e76879e0a2a28cb1aebe5ff936d0b534d7d8d23e380467500000000000000000000000056178a0d5f301baf6cf3e1cd53d9863437345bf900000000000000000000000074de5d4fcbf63e00296fd95d33236b9794016631000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000095ad61b0a150d79219dcf64e1e6cc01f0b64c4ce000000000000000000000000000000000000000000fe30137375b8c39c8a555700000000000000000000000000000000000000000000000000000000c7a173040000000000000000000000000000000000000000000000000000000000000000f89b94a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa000000000000000000000000074de5d4fcbf63e00296fd95d33236b9794016631a00000000000000000000000002acf35c9a3f4c5c3f4c78ef5fb64c3ee82f07c45a00000000000000000000000000000000000000000000000000000000001bf2c34f89b94a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa000000000000000000000000074de5d4fcbf63e00296fd95d33236b9794016631a0000000000000000000000000ed6021c55398a3690c2ac3ae45c65decbd36c83da000000000000000000000000000000000000000000000000000000000c5e246d0f87b94881d40237659c251811cec9c364ef91dc08d300cf863a0beee1e6e7fe307ddcf84b0a16137a4430ad5e2480fc4f4a8e250ab56ccd7630da0a8dc30b66c6d4a8aac3d15925bfca09e42cac4a00c50f9949154b045088e2ac2a0000000000000000000000000ed6021c55398a3690c2ac3ae45c65decbd36c83d80";
    const RECEIPT_4: &str = "02f901098083076f7eb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0";
    const RECEIPT_5: &str = "02f90109808308851fb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0";
    const RECEIPT_6: &str = "f90109018308d727b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0";
    const RECEIPT_7: &str = "f901a70183098b44b9010000000000000000000000000000000000000000010000000001000000000000000000000000000000000000000000010000000000000000040000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000080000000000000000000000000000000000100000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000f89df89b94dac17f958d2ee523a2206206994597c13d831ec7f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa00000000000000000000000008b8a4abc707f16da24b795e3e46ed22975a9d329a000000000000000000000000088bd4648737098aa9096bfba765dec014d2a11c1a00000000000000000000000000000000000000000000000000000000010ea71c0";
    const RECEIPT_8: &str = "f901a701830a8215b9010000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000010000000000000000040000000000000000000000000000000000000008000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000080000000000000000000000000000000000100800000000002000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000f89df89b94dac17f958d2ee523a2206206994597c13d831ec7f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa00000000000000000000000008b8a4abc707f16da24b795e3e46ed22975a9d329a00000000000000000000000000f893a99b0165d3c92bc7d578afbc2104500761aa0000000000000000000000000000000000000000000000000000000002f71ff00";
    const RECEIPT_9: &str = "02f901a701830b2cdbb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000010000000080000000000000000000000200008000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000080000000000000000000000020000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000f89df89b94dac17f958d2ee523a2206206994597c13d831ec7f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000b24abf582bab677c3bc8aa60706d212284a35b51a00000000000000000000000007abe0ce388281d2acf297cb089caef3819b13448a00000000000000000000000000000000000000000000000000000002fcc3cce80";
    const RECEIPT_10: &str = "02f9010901830b7ee3b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0";
    const RECEIPT_11: &str = "02f9010901830bd0ebb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0";
    const RECEIPT_12: &str = "02f9058401830e7c79b9010000000000000000000000000000000000000000000000000000000000000000002000100000000000000000020000000000000000000200000000000000000000000000000000000000000001002000000000000001000000000000000000000000000000020800000000000000000800000010000000000000000000000000000000000000000000000000000000000000400480000000000000000040000000000000001000000000000000000000000000000000000000000000000000000008000000000000000000000000000000004000000000000000000000000020000000000000000000000200000000000000000000000000000000010000000000f90479f9033c945edd5f803b831b47715ad3e11a90dd244f0cd0a9f842a0f6a97944f31ea060dfde0566e4167c1a1082551e64b60ecb14d599a9d023d451a00000000000000000000000000000000000000000000000000000000000000af6b902e00000000000000000000000000000000000000000000000000000000002740989000000000000000000000000f6e7dba31369024f0044f24ce5dc2c612b298edd00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000002a00000000000000000000000723b92452ba80acd1bfd31e98693a5110001249e01000000000000000000000000000000000000000000000000000000000000000f00000000000000000000000000000000000000000000000000000000025d005000000000000000000000000000000000000000000000000000000000025eb3a800000000000000000000000000000000000000000000000000000000025f4e9d0000000000000000000000000000000000000000000000000000000002616fa00000000000000000000000000000000000000000000000000000000002662a9000000000000000000000000000000000000000000000000000000000026dcbb000000000000000000000000000000000000000000000000000000000027409890000000000000000000000000000000000000000000000000000000002740989000000000000000000000000000000000000000000000000000000000274098900000000000000000000000000000000000000000000000000000000027621e400000000000000000000000000000000000000000000000000000000027621e400000000000000000000000000000000000000000000000000000000027621e400000000000000000000000000000000000000000000000000000000027818c00000000000000000000000000000000000000000000000000000000002920c5a0000000000000000000000000000000000000000000000000000000002920c5a000000000000000000000000000000000000000000000000000000000000000f0408000b05020c070f090a0106030e0000000000000000000000000000000000f89b945edd5f803b831b47715ad3e11a90dd244f0cd0a9f863a00109fc6f55cf40689f02fbaad7af7fe7bbac8a3d2186600afc7d3e10cac60271a00000000000000000000000000000000000000000000000000000000000000af6a00000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000627d9afaf89b945edd5f803b831b47715ad3e11a90dd244f0cd0a9f863a00559884fd3a460db3073b7fc896cc77986f16e378210ded43186175bf646fc5fa00000000000000000000000000000000000000000000000000000000002740989a00000000000000000000000000000000000000000000000000000000000000af6a000000000000000000000000000000000000000000000000000000000627d9afa";
    const RECEIPT_13: &str = "02f901a701830f3a12b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000108000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000100000000000000000000000000010000000000000000000020000000000000200000000000000001000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001f89df89b94a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa000000000000000000000000021a31ee1afc51d94c2efccaa2092ad1028285549a0000000000000000000000000f841a830cd94f6f00be674c81f57d5fcbbee2857a0000000000000000000000000000000000000000000000000000000038869ffb0";
    const RECEIPT_14: &str = "02f901a70183103a6bb9010000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000008000000000000000000000000000000000000000000000000000000000000000000000000200000000000000040000010000000000000000000000000000000000000000040000000010000000000000000000000000000000000200000000000000000000000000000000000000008000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000f89df89b94a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000503828976d22510aad0201ac7ec88293211d23daa00000000000000000000000008954b57277a9d7260bb5535afa83d53bf343637ca0000000000000000000000000000000000000000000000000000000001e742c50";
    const RECEIPT_15: &str = "02f901a70183113154b9010000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000010400000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000002000000000000000000000000000000100000000000000080000000000080000000000000000000000000000001000000000000000002000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000f89df89b94dac17f958d2ee523a2206206994597c13d831ec7f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000dfd5293d8e347dfe59e90efd55b2956a1343963da00000000000000000000000004bb8adce5e7297f2d8c5a2302a68d65eb44158cda0000000000000000000000000000000000000000000000000000000000d41fae9";
    const RECEIPT_16: &str = "02f901a7018312e726b9010000000000400000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000008000000000000000000000200000000000000000000000000000000000000000000000000200000000000000040000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000802000000002000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000f89df89b9488df592f8eb5d7bd38bfef7deb0fbc02cf3778a0f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000503828976d22510aad0201ac7ec88293211d23daa00000000000000000000000004b7575ef97285f846c944eee2e155bd3ceb65343a0000000000000000000000000000000000000000000000025e320a2817417f400";
    const RECEIPT_17: &str = "02f90109018313bba9b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0";
    const RECEIPT_18: &str = "02f901090183140db1b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0";
}
