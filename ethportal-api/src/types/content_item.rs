use ethereum_types::{H256, U256};
use reth_primitives::{Header, Receipt, TransactionSigned};
use reth_rlp::{Decodable, Encodable};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, FixedVector, VariableList};

#[derive(Clone, Debug)]
pub enum ContentItemDecodeError {
    Rlp(reth_rlp::DecodeError),
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

pub trait ContentItem: Sized {
    fn encode(&self, buf: &mut [u8]);
    fn decode(buf: &[u8]) -> Result<Self, ContentItemDecodeError>;
}

impl ContentItem for Vec<Receipt> {
    fn encode(&self, buf: &mut [u8]) {
        let ssz: VariableList<VariableList<u8, typenum::U134217728>, typenum::U16384>;
        let receipts: Vec<VariableList<u8, typenum::U134217728>> = self
            .into_iter()
            .map(|receipt| {
                let rlp = bytes::BytesMut::new();
                Encodable::encode(&self, &mut rlp);
                let ssz: VariableList<u8, typenum::U134217728> = VariableList::from(rlp.to_vec());
                ssz
            })
            .collect();
        ssz = VariableList::from(receipts);
        buf.copy_from_slice(&ssz::ssz_encode(&ssz));
    }

    fn decode(buf: &[u8]) -> Result<Self, ContentItemDecodeError> {
        let ssz: VariableList<VariableList<u8, typenum::U134217728>, typenum::U16384> =
            VariableList::from_ssz_bytes(buf)?;
        let receipts: Result<Self, ContentItemDecodeError> = ssz
            .into_iter()
            .map(|ssz| {
                Decodable::decode(&mut &**ssz).map_err(|err| ContentItemDecodeError::from(err))
            })
            .collect();
        Ok(receipts?)
    }
}

impl ContentItem for Header {
    fn encode(&self, buf: &mut [u8]) {
        Encodable::encode(&self, &mut buf);
    }

    fn decode(buf: &[u8]) -> Result<Self, ContentItemDecodeError> {
        let header: Header = Decodable::decode(&mut buf)?;
        Ok(header)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderWithProof {
    header: Header,
    proof: Option<[H256; 15]>,
}

#[derive(Decode, Encode)]
struct HeaderWithProofSszContainer {
    header: VariableList<u8, typenum::U2048>,
    proof: SszOption<FixedVector<H256, typenum::U15>>,
}

impl ContentItem for HeaderWithProof {
    fn encode(&self, buf: &mut [u8]) {
        let header = bytes::BytesMut::new();
        Encodable::encode(&self.header, &mut header);
        let header: VariableList<u8, typenum::U2048> = VariableList::from(header.to_vec());
        let proof = match self.proof {
            Some(proof) => SszOption(Some(FixedVector::from(proof.to_vec()))),
            None => SszOption(None),
        };

        let container = HeaderWithProofSszContainer { header, proof };
        let ssz = ssz::ssz_encode(&container);
        buf.copy_from_slice(&ssz);
    }

    fn decode(buf: &[u8]) -> Result<Self, ContentItemDecodeError> {
        let container = HeaderWithProofSszContainer::from_ssz_bytes(buf)?;
        let header: Header = Decodable::decode(&mut &*container.header)?;
        let proof = match container.proof.0 {
            Some(proof) => {
                let mut arr: [H256; 15];
                arr.copy_from_slice(&proof);
                Some(arr)
            }
            None => None,
        };

        Ok(Self { header, proof })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockBody {
    transactions: Vec<TransactionSigned>,
    uncles: Vec<Header>,
}

#[derive(Decode, Encode)]
struct BlockBodySszContainer {
    transactions: VariableList<VariableList<u8, typenum::U16777216>, typenum::U16384>,
    uncles: VariableList<u8, typenum::U131072>,
}

impl ContentItem for BlockBody {
    fn encode(&self, buf: &mut [u8]) {
        let transactions: Vec<VariableList<u8, typenum::U16777216>> = Vec::new();
        for transaction in self.transactions {
            let rlp = bytes::BytesMut::new();
            Encodable::encode(&transaction, &mut rlp);
            transactions.push(VariableList::from(rlp.to_vec()));
        }
        let transactions: VariableList<VariableList<u8, typenum::U16777216>, typenum::U16384> =
            VariableList::from(transactions);

        let uncles_rlp = bytes::BytesMut::new();
        Encodable::encode(&self.uncles, &mut uncles_rlp);
        let uncles: VariableList<u8, typenum::U131072> = VariableList::from(uncles_rlp.to_vec());

        let container = BlockBodySszContainer {
            transactions,
            uncles,
        };
        buf.copy_from_slice(&ssz::ssz_encode(&container));
    }

    fn decode(buf: &[u8]) -> Result<Self, ContentItemDecodeError> {
        let container = BlockBodySszContainer::from_ssz_bytes(&buf).unwrap();
        let transactions: Vec<TransactionSigned> = container
            .transactions
            .into_iter()
            .map(|tx| Decodable::decode(&mut &**tx).unwrap())
            .collect();
        let uncles: Vec<Header> = Decodable::decode(&mut &*container.uncles).unwrap();

        Ok(Self {
            transactions,
            uncles,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Decode, Encode)]
pub struct HeaderRecord {
    hash: H256,
    total_difficulty: U256,
}

pub type EpochAccumulator = FixedVector<HeaderRecord, typenum::U8192>;

impl ContentItem for EpochAccumulator {
    fn encode(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&ssz::ssz_encode(self));
    }

    fn decode(buf: &[u8]) -> Result<Self, ContentItemDecodeError> {
        let acc = EpochAccumulator::from_ssz_bytes(buf)?;
        Ok(acc)
    }
}

/// Portal History content items.
/// Supports both BlockHeaderWithProof and the depreciated BlockHeader content types
#[derive(Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum HistoryContentItem {
    BlockHeaderWithProof(HeaderWithProof),
    BlockHeader(Header),
    BlockBody(BlockBody),
    Receipts(Vec<Receipt>),
    EpochAccumulator(EpochAccumulator),
}

impl Serialize for HistoryContentItem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut encoded = bytes::BytesMut::new();
        match self {
            Self::BlockHeaderWithProof(item) => item.encode(&mut encoded),
            Self::BlockHeader(item) => ContentItem::encode(item, &mut encoded),
            Self::BlockBody(item) => item.encode(&mut encoded),
            Self::Receipts(item) => ContentItem::encode(item, &mut encoded),
            Self::EpochAccumulator(item) => encoded.copy_from_slice(&ssz::ssz_encode(item)),
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
        let content_bytes =
            hex::decode(s.strip_prefix("0x").unwrap_or(&s)).map_err(serde::de::Error::custom)?;

        if let Ok(item) = HeaderWithProof::decode(&content_bytes) {
            return Ok(Self::BlockHeaderWithProof(item));
        }

        if let Ok(item) = <Header as ContentItem>::decode(&content_bytes) {
            return Ok(Self::BlockHeader(item));
        }

        if let Ok(item) = BlockBody::decode(&content_bytes) {
            return Ok(Self::BlockBody(item));
        }

        if let Ok(item) = <Vec<Receipt> as ContentItem>::decode(&content_bytes) {
            return Ok(Self::Receipts(item));
        }

        if let Ok(item) = EpochAccumulator::decode(&content_bytes) {
            return Ok(Self::EpochAccumulator(item));
        }

        Err(serde::de::Error::custom(
            "unable to deserialize to any history content item",
        ))
    }
}

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
            Option::Some(ref inner) => {
                let union_selector: u8 = 1u8;
                buf.push(union_selector);
                inner.ssz_append(buf);
            }
        }
    }
    fn ssz_bytes_len(&self) -> usize {
        match self.as_ref() {
            Option::None => 1usize,
            Option::Some(ref inner) => inner
                .ssz_bytes_len()
                .checked_add(1)
                .expect("encoded length must be less than usize::max_value"),
        }
    }
}
