use ethereum_types::{H256, U256};
use reth_primitives::proofs::{
    calculate_ommers_root, calculate_receipt_root, calculate_transaction_root,
};
use reth_primitives::{Header, Receipt, TransactionSigned};
use reth_rlp::{Decodable, Encodable};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, FixedVector, VariableList};
use tree_hash_derive::TreeHash;

/// An error decoding a portal network content item.
#[derive(Clone, Debug)]
pub enum ContentItemDecodeError {
    /// RLP decode error.
    Rlp(reth_rlp::DecodeError),
    /// SSZ decode error.
    Ssz(ssz::DecodeError),
}

impl From<reth_rlp::DecodeError> for ContentItemDecodeError {
    fn from(err: reth_rlp::DecodeError) -> Self {
        Self::Rlp(err)
    }
}

impl From<ssz::DecodeError> for ContentItemDecodeError {
    fn from(err: ssz::DecodeError) -> Self {
        Self::Ssz(err)
    }
}

/// An encodable portal network content item.
pub trait ContentItem: Sized {
    /// Encodes the content item, appending the encoded bytes to `buf`.
    fn encode(&self, buf: &mut Vec<u8>);
    /// Decodes `buf` into a content item.
    fn decode(buf: &[u8]) -> Result<Self, ContentItemDecodeError>;
}

type SszReceipt = VariableList<u8, typenum::U134217728>;
type SszReceiptList = VariableList<SszReceipt, typenum::U16384>;

impl ContentItem for Receipts {
    fn encode(&self, buf: &mut Vec<u8>) {
        let receipts: Vec<SszReceipt> = self
            .0
            .iter()
            .map(|receipt| {
                let mut rlp = bytes::BytesMut::new();
                Encodable::encode(&receipt, &mut rlp);
                VariableList::from(rlp.to_vec())
            })
            .collect();
        let ssz: SszReceiptList = VariableList::from(receipts);
        buf.append(&mut ssz::ssz_encode(&ssz));
    }

    fn decode(buf: &[u8]) -> Result<Self, ContentItemDecodeError> {
        let ssz: SszReceiptList = VariableList::from_ssz_bytes(buf)?;
        let receipts: Result<Vec<Receipt>, ContentItemDecodeError> = ssz
            .into_iter()
            .map(|ssz| Decodable::decode(&mut &**ssz).map_err(ContentItemDecodeError::from))
            .collect();
        let receipts = Self(receipts?);
        Ok(receipts)
    }
}

impl ContentItem for Header {
    fn encode(&self, buf: &mut Vec<u8>) {
        Encodable::encode(&self, &mut &mut *buf);
    }

    fn decode(buf: &[u8]) -> Result<Self, ContentItemDecodeError> {
        let header: Header = Decodable::decode(&mut &*buf)?;
        Ok(header)
    }
}

/// The length of the Merkle proof for the inclusion of a block header in a particular epoch
/// accumulator.
pub const EPOCH_ACC_PROOF_LEN: usize = 15;

/// A block header with its corresponding proof against an epoch accumulator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderWithProof {
    /// The block header.
    pub header: Header,
    /// An optional epoch accumulator proof for the block header.
    ///
    /// Note: `proof` should only be `None` if `header` corresponds to a post-merge block.
    ///
    /// XXX: at some point we will need to support another type of proof
    pub proof: Option<[H256; EPOCH_ACC_PROOF_LEN]>,
}

type SszEncodedHeader = VariableList<u8, typenum::U2048>;
type SszHeaderProof = FixedVector<H256, typenum::U15>;

#[derive(Decode, Encode)]
struct HeaderWithProofSszContainer {
    header: SszEncodedHeader,
    proof: SszOption<SszHeaderProof>,
}

impl ContentItem for HeaderWithProof {
    fn encode(&self, buf: &mut Vec<u8>) {
        let mut header = bytes::BytesMut::new();
        Encodable::encode(&self.header, &mut header);
        let header: SszEncodedHeader = VariableList::from(header.to_vec());
        let proof = match self.proof {
            Some(proof) => SszOption(Some(FixedVector::from(proof.to_vec()))),
            None => SszOption(None),
        };

        let container = HeaderWithProofSszContainer { header, proof };
        buf.append(&mut ssz::ssz_encode(&container));
    }

    fn decode(buf: &[u8]) -> Result<Self, ContentItemDecodeError> {
        let container = HeaderWithProofSszContainer::from_ssz_bytes(buf)?;
        let header: Header = Decodable::decode(&mut &*container.header)?;
        let proof = match container.proof.0 {
            Some(proof) => {
                let mut arr: [H256; EPOCH_ACC_PROOF_LEN] = [H256::zero(); EPOCH_ACC_PROOF_LEN];
                arr.copy_from_slice(&proof);
                Some(arr)
            }
            None => None,
        };

        Ok(Self { header, proof })
    }
}

/// Receipts
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipts(pub Vec<Receipt>);

impl Receipts {
    pub fn root(&self) -> H256 {
        let reth_h256 = calculate_receipt_root(self.0.iter());
        H256::from_slice(&reth_h256[..])
    }
}

/// A block body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockBody {
    /// The list of transactions within the block.
    pub transactions: Vec<TransactionSigned>,
    /// The list of block headers for the "uncles" of the block.
    pub uncles: Vec<Header>,
}

type SszTransaction = VariableList<u8, typenum::U16777216>;
type SszTransactionList = VariableList<SszTransaction, typenum::U16384>;
type SszUncles = VariableList<u8, typenum::U131072>;

impl BlockBody {
    pub fn uncles_root(&self) -> H256 {
        let reth_h256 = calculate_ommers_root(self.uncles.iter());
        H256::from_slice(&reth_h256[..])
    }

    pub fn transactions_root(&self) -> H256 {
        let reth_h256 = calculate_transaction_root(self.transactions.iter());
        H256::from_slice(&reth_h256[..])
    }
}

#[derive(Decode, Encode)]
struct BlockBodySszContainer {
    transactions: SszTransactionList,
    uncles: SszUncles,
}

impl ContentItem for BlockBody {
    fn encode(&self, buf: &mut Vec<u8>) {
        let mut transactions: Vec<SszTransaction> = Vec::new();
        for transaction in self.transactions.iter() {
            let mut rlp = bytes::BytesMut::new();
            Encodable::encode(&transaction, &mut rlp);
            transactions.push(VariableList::from(rlp.to_vec()));
        }
        let transactions: SszTransactionList = VariableList::from(transactions);

        let mut uncles_rlp = bytes::BytesMut::new();
        Encodable::encode(&self.uncles, &mut uncles_rlp);
        let uncles: SszUncles = VariableList::from(uncles_rlp.to_vec());

        let container = BlockBodySszContainer {
            transactions,
            uncles,
        };
        buf.append(&mut ssz::ssz_encode(&container));
    }

    fn decode(buf: &[u8]) -> Result<Self, ContentItemDecodeError> {
        let container = BlockBodySszContainer::from_ssz_bytes(buf)?;
        let transactions: Result<Vec<TransactionSigned>, _> = container
            .transactions
            .into_iter()
            .map(|tx| Decodable::decode(&mut &**tx))
            .collect();
        let uncles: Vec<Header> = Decodable::decode(&mut &*container.uncles)?;

        Ok(Self {
            transactions: transactions?,
            uncles,
        })
    }
}

/// A header element of an epoch accumulator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Decode, Encode, TreeHash)]
pub struct HeaderRecord {
    /// The hash of the block.
    pub hash: tree_hash::Hash256,
    /// The cumulative total difficulty from genesis up to and including this block.
    pub total_difficulty: U256,
}

pub type EpochAccumulator = VariableList<HeaderRecord, typenum::U8192>;

impl ContentItem for EpochAccumulator {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.append(&mut ssz::ssz_encode(self));
    }

    fn decode(buf: &[u8]) -> Result<Self, ContentItemDecodeError> {
        let acc = EpochAccumulator::from_ssz_bytes(buf)?;
        Ok(acc)
    }
}

/// A Portal History content item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HistoryContentItem {
    BlockHeaderWithProof(HeaderWithProof),
    BlockBody(BlockBody),
    Receipts(Receipts),
    EpochAccumulator(EpochAccumulator),
    /// A placeholder for data that could not be interpreted as any of the valid content types.
    Unknown(String),
}

impl ContentItem for HistoryContentItem {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::BlockHeaderWithProof(item) => item.encode(buf),
            Self::BlockBody(item) => item.encode(buf),
            Self::Receipts(item) => ContentItem::encode(item, buf),
            Self::EpochAccumulator(item) => item.encode(buf),
            Self::Unknown(item) => buf.append(&mut item.clone().into_bytes()),
        }
    }

    fn decode(buf: &[u8]) -> Result<Self, ContentItemDecodeError> {
        if let Ok(item) = HeaderWithProof::decode(buf) {
            return Ok(Self::BlockHeaderWithProof(item));
        }

        if let Ok(item) = BlockBody::decode(buf) {
            return Ok(Self::BlockBody(item));
        }

        if let Ok(item) = ContentItem::decode(buf) {
            return Ok(Self::Receipts(item));
        }

        if let Ok(item) = EpochAccumulator::decode(buf) {
            return Ok(Self::EpochAccumulator(item));
        }

        Ok(Self::Unknown(hex::encode(buf)))
    }
}

impl Serialize for HistoryContentItem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut encoded = Vec::new();
        match self {
            Self::BlockHeaderWithProof(item) => item.encode(&mut encoded),
            Self::BlockBody(item) => item.encode(&mut encoded),
            Self::Receipts(item) => ContentItem::encode(item, &mut encoded),
            Self::EpochAccumulator(item) => ContentItem::encode(item, &mut encoded),
            Self::Unknown(item) => {
                if item.is_empty() {
                    return serializer.serialize_str("0x0");
                }
                encoded.append(&mut item.clone().into_bytes());
            }
        }
        serializer.serialize_str(&format!("0x{}", hex::encode(encoded)))
    }
}

impl<'de> Deserialize<'de> for HistoryContentItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.as_str() == "0x0" {
            return Ok(Self::Unknown(String::from("")));
        }

        let content_bytes =
            hex::decode(s.strip_prefix("0x").unwrap_or(&s)).map_err(serde::de::Error::custom)?;

        if let Ok(item) = HeaderWithProof::decode(&content_bytes) {
            return Ok(Self::BlockHeaderWithProof(item));
        }

        if let Ok(item) = BlockBody::decode(&content_bytes) {
            return Ok(Self::BlockBody(item));
        }

        if let Ok(item) = <Receipts as ContentItem>::decode(&content_bytes) {
            return Ok(Self::Receipts(item));
        }

        if let Ok(item) = EpochAccumulator::decode(&content_bytes) {
            return Ok(Self::EpochAccumulator(item));
        }

        Ok(Self::Unknown(hex::encode(content_bytes)))
    }
}

/// A wrapper struct for an optional SSZ value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SszOption<T>(Option<T>);

impl<T> std::ops::Deref for SszOption<T> {
    type Target = Option<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: ssz::Decode> ssz::Decode for SszOption<T> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let (selector, body) = ssz::split_union_bytes(bytes)?;
        match selector.into() {
            0u8 => Ok(Self(None)),
            1u8 => <T as ssz::Decode>::from_ssz_bytes(body).map(|t| Self(Some(t))),
            other => Err(ssz::DecodeError::UnionSelectorInvalid(other)),
        }
    }
}

impl<T: ssz::Encode> ssz::Encode for SszOption<T> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        match self.as_ref() {
            Option::None => {
                let union_selector: u8 = 0u8;
                buf.push(union_selector);
            }
            Option::Some(inner) => {
                let union_selector: u8 = 1u8;
                buf.push(union_selector);
                inner.ssz_append(buf);
            }
        }
    }
    fn ssz_bytes_len(&self) -> usize {
        match self.as_ref() {
            Option::None => 1usize,
            Option::Some(inner) => inner
                .ssz_bytes_len()
                .checked_add(1)
                .expect("encoded length must be less than usize::max_value"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use reth_primitives::{Transaction, TxEip1559, TxEip2930, TxLegacy, TxType};
    use serde_json::Value;
    use ssz::Encode;

    use std::fs;

    /// Max number of blocks / epoch = 2 ** 13
    pub const EPOCH_SIZE: usize = 8192;

    #[test]
    fn header_with_proof_encode_decode_fluffy() {
        let file = fs::read_to_string("./src/assets/test/fluffy_header_with_proofs.json").unwrap();
        let json: Value = serde_json::from_str(&file).unwrap();
        let json = json.as_object().unwrap();
        for (block_num, obj) in json {
            let block_num: u64 = block_num.parse().unwrap();
            let header_with_proof = obj.get("value").unwrap().as_str().unwrap();
            let header_with_proof_encoded =
                hex::decode(header_with_proof.strip_prefix("0x").unwrap()).unwrap();
            let header_with_proof = HeaderWithProof::decode(&header_with_proof_encoded).unwrap();

            assert_eq!(header_with_proof.header.number, block_num);

            let mut encoded = Vec::new();
            header_with_proof.encode(&mut encoded);
            assert_eq!(encoded, header_with_proof_encoded);
        }
    }

    #[test]
    fn block_body_encode_decode() {
        let mut tx_one: TransactionSigned = Default::default();
        tx_one.transaction = Transaction::Legacy(TxLegacy::default());
        tx_one.hash = tx_one.recalculate_hash();

        let mut tx_two: TransactionSigned = Default::default();
        tx_two.transaction = Transaction::Eip1559(TxEip1559::default());
        tx_two.hash = tx_two.recalculate_hash();

        let mut tx_three: TransactionSigned = Default::default();
        tx_three.transaction = Transaction::Eip2930(TxEip2930::default());
        tx_three.hash = tx_three.recalculate_hash();

        let transactions = vec![tx_one.clone(), tx_two.clone(), tx_three.clone()];

        let header_one = Header {
            number: 1,
            ..Default::default()
        };

        let header_two = Header {
            number: 2,
            ..Default::default()
        };

        let uncles = vec![header_one.clone(), header_two.clone()];

        let body = BlockBody {
            transactions,
            uncles,
        };

        let mut portal_encoded = Vec::new();
        ContentItem::encode(&body, &mut portal_encoded);
        let portal_decoded: BlockBody = ContentItem::decode(&portal_encoded).unwrap();
        assert_eq!(portal_decoded.transactions.len(), 3);
        assert_eq!(portal_decoded.transactions[0], tx_one);
        assert_eq!(portal_decoded.transactions[1], tx_two);
        assert_eq!(portal_decoded.transactions[2], tx_three);
        assert_eq!(portal_decoded.uncles.len(), 2);
        assert_eq!(portal_decoded.uncles[0], header_one);
        assert_eq!(portal_decoded.uncles[1], header_two);

        let serde_encoded = serde_json::to_string(&HistoryContentItem::BlockBody(body)).unwrap();
        let serde_decoded: HistoryContentItem = serde_json::from_str(&serde_encoded).unwrap();

        if let HistoryContentItem::BlockBody(decoded) = serde_decoded {
            assert_eq!(decoded.transactions.len(), 3);
            assert_eq!(decoded.transactions[0], tx_one);
            assert_eq!(decoded.transactions[1], tx_two);
            assert_eq!(decoded.transactions[2], tx_three);
            assert_eq!(portal_decoded.uncles.len(), 2);
            assert_eq!(portal_decoded.uncles[0], header_one);
            assert_eq!(portal_decoded.uncles[1], header_two);
        } else {
            panic!("incorrect content item");
        }
    }

    #[test]
    fn receipts_encode_decode() {
        let receipt_one = Receipt {
            tx_type: TxType::Legacy,
            success: true,
            cumulative_gas_used: 100,
            ..Default::default()
        };

        let receipt_two = Receipt {
            tx_type: TxType::EIP1559,
            success: false,
            cumulative_gas_used: 1000,
            ..Default::default()
        };

        let receipt_three = Receipt {
            tx_type: TxType::EIP2930,
            success: false,
            cumulative_gas_used: 10000,
            ..Default::default()
        };

        let receipts = Receipts(vec![
            receipt_one.clone(),
            receipt_two.clone(),
            receipt_three.clone(),
        ]);

        let mut portal_encoded = Vec::new();
        ContentItem::encode(&receipts, &mut portal_encoded);
        let portal_decoded: Receipts = ContentItem::decode(&portal_encoded).unwrap();
        assert_eq!(portal_decoded.0.len(), 3);
        assert_eq!(portal_decoded.0[0], receipt_one);
        assert_eq!(portal_decoded.0[1], receipt_two);
        assert_eq!(portal_decoded.0[2], receipt_three);

        let serde_encoded = serde_json::to_string(&HistoryContentItem::Receipts(receipts)).unwrap();
        let serde_decoded: HistoryContentItem = serde_json::from_str(&serde_encoded).unwrap();

        if let HistoryContentItem::Receipts(decoded) = serde_decoded {
            assert_eq!(decoded.0.len(), 3);
            assert_eq!(decoded.0[0], receipt_one);
            assert_eq!(decoded.0[1], receipt_two);
            assert_eq!(decoded.0[2], receipt_three);
        } else {
            panic!("incorrect content item");
        }
    }

    #[test]
    fn ssz_serde_encode_decode_fluffy_epoch_accumulator() {
        // values sourced from: https://github.com/status-im/portal-spec-tests
        let epoch_acc_ssz = fs::read("./src/assets/test/fluffy_epoch_acc.bin").unwrap();
        let epoch_acc = EpochAccumulator::decode(&epoch_acc_ssz).unwrap();
        assert_eq!(epoch_acc.len(), EPOCH_SIZE);
        assert_eq!(epoch_acc.as_ssz_bytes(), epoch_acc_ssz);
    }

    #[test]
    fn ssz_serde_encode_decode_ultralight_epoch_accumulator() {
        let epoch_acc_hex =
            fs::read_to_string("./src/assets/test/ultralight_testEpoch.hex").unwrap();
        let epoch_acc_ssz = hex::decode(epoch_acc_hex.strip_prefix("0x").unwrap()).unwrap();
        let epoch_acc = EpochAccumulator::decode(&epoch_acc_ssz).unwrap();
        assert_eq!(epoch_acc.len(), EPOCH_SIZE);
        assert_eq!(epoch_acc.as_ssz_bytes(), epoch_acc_ssz);
    }
}
