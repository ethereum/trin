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
                let mut rlp = bytes::BytesMut::new();
                Encodable::encode(&receipt, &mut rlp);
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
        Encodable::encode(&self, &mut &mut *buf);
    }

    fn decode(buf: &[u8]) -> Result<Self, ContentItemDecodeError> {
        let header: Header = Decodable::decode(&mut &*buf)?;
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
        let mut header = bytes::BytesMut::new();
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
                let mut arr: [H256; 15] = [H256::zero(); 15];
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
        let mut transactions: Vec<VariableList<u8, typenum::U16777216>> = Vec::new();
        for transaction in self.transactions.iter() {
            let mut rlp = bytes::BytesMut::new();
            Encodable::encode(&transaction, &mut rlp);
            transactions.push(VariableList::from(rlp.to_vec()));
        }
        let transactions: VariableList<VariableList<u8, typenum::U16777216>, typenum::U16384> =
            VariableList::from(transactions);

        let mut uncles_rlp = bytes::BytesMut::new();
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

pub type EpochAccumulator = VariableList<HeaderRecord, typenum::U8192>;

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
            Self::EpochAccumulator(item) => ContentItem::encode(item, &mut encoded),
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

#[cfg(test)]
mod test {
    use super::*;
    use ssz::{Decode, Encode};
    use std::fs;

    /// Max number of blocks / epoch = 2 ** 13
    pub const EPOCH_SIZE: usize = 8192;

    #[test]
    fn header_with_proof_encode_decode() {
        const TEST_VEC_ONE: &str = "0x0800000022020000f90217a08e38b4dbf6b11fcc3b9dee84fb7986e29ca0a02cecd8977c161ff7333329681ea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942a65aca4d5fc5b5c859090a6c34d164135398226a07dd4aabb93795feba9866821c0c7d6a992eda7fbdd412ea0f715059f9654ef23a0c61c50a0a2800ddc5e9984af4e6668de96aee1584179b3141f458ffa7d4ecec6a0b873ddefdb56d448343d13b188241a4919b2de10cccea2ea573acf8dbc839befb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000860b6b4bbd735f830f4241832fefd88252088456bfb41a98d783010303844765746887676f312e352e31856c696e7578a0d5332614a151dd917b84fc5ff62580d7099edb7c37e0ac843d873de978d50352889112b8c2b377fbe801c971eaaa41600563000000000000000000000000000000000000000000000000629f9dbe275316ef21073133b8ecec062a44e20201be7b24a22c56db91df336f0c71aaaec1b3526027a54b15387ef014fcd18bb46e90e05657b46418fd326e785392c40ec6d38f000042798fee52ed833ff376b1d5a95dc7c2356dc8d8d02e30b704e9ee8e4d712920a18fd4e8833a7979a14e5b972d4b27958dcfa5187e3aa14d61c29c3fda0fb425078a0479c5ea375ff95ad7780d0cdc87012009fd4a3dd003b06c7a28d6188e6be50ac544548cc7e3ee6cd07a8129f5c6d4d494b62ee8d96d26d0875bc87b56be0bf3e45846c0e3773abfccc239fdab29640b4e2aef297efcc6cb89b00a2566221cb4197ece3f66c24ea89969bd16265a74910aaf08d775116191117416b8799d0984f452a6fba19623442a7f199ef1627f1ae7295963a67db5534a292f98edbfb419ed85756abe76cd2d2bff8eb9b848b1e7b80b8274bbc469a36dce58b48ae57be6312bca843463ac45c54122a9f3fa9dca124b0fd50bce300708549c77b81b031278b9d193464f5e4b14769f6018055a457a577c508e811bcf55b297df3509f3db7e66ec68451e25acfbf935200e246f71e3c48240d00020000000000000000000000000000000000000000000000000000000000000";

        const TEST_VEC_TWO: &str = "0x0800000022020000f90217a0cb5cab7266694daa0d28cbf40496c08dd30bf732c41e0455e7ad389c10d79f4fa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479495581ea0c5b362933f3523138f54d51eae817211a0643430d1afc3f02ce5249e4ba5979fb8601b1907a5923a4a74d36d66321a27e5a0dbdf7457111e50e435853974d5412c2151fde6e3c2e3f5aecc253aa4cb21fce2a097097902b6b4d6b695ef16b923e33b8780d95cf4bd54540ac450deb019d07647b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000860b69de53fcb1830f4242832fefd882f6188456bfb42e98d783010303844765746887676f312e352e31856c696e7578a0a01f9d00ac510a726f883459834e30cfe085f47b04e22f72207f5a9e9d652ca6881c080c4ec6f2553b017a6e3e89ab6b056300000000000000000000000000000000000000000000000030a7f33265c53f74e978e394ce395aaf1247e8d878ad7924c730beedf21f997ef4cb3507d87cf63a4e94fd8d559a5aa29598a0fbc997b3d7abb68cb9239d83c35392c40ec6d38f000042798fee52ed833ff376b1d5a95dc7c2356dc8d8d02e30b704e9ee8e4d712920a18fd4e8833a7979a14e5b972d4b27958dcfa5187e3aa14d61c29c3fda0fb425078a0479c5ea375ff95ad7780d0cdc87012009fd4a3dd003b06c7a28d6188e6be50ac544548cc7e3ee6cd07a8129f5c6d4d494b62ee8d96d26d0875bc87b56be0bf3e45846c0e3773abfccc239fdab29640b4e2aef297efcc6cb89b00a2566221cb4197ece3f66c24ea89969bd16265a74910aaf08d775116191117416b8799d0984f452a6fba19623442a7f199ef1627f1ae7295963a67db5534a292f98edbfb419ed85756abe76cd2d2bff8eb9b848b1e7b80b8274bbc469a36dce58b48ae57be6312bca843463ac45c54122a9f3fa9dca124b0fd50bce300708549c77b81b031278b9d193464f5e4b14769f6018055a457a577c508e811bcf55b297df3509f3db7e66ec68451e25acfbf935200e246f71e3c48240d00020000000000000000000000000000000000000000000000000000000000000";

        let bytes = &hex::decode(TEST_VEC_ONE.strip_prefix("0x").unwrap()).unwrap();
        let _ = HeaderWithProof::decode(bytes).unwrap();

        let bytes = &hex::decode(TEST_VEC_TWO.strip_prefix("0x").unwrap()).unwrap();
        let _ = HeaderWithProof::decode(bytes).unwrap();
    }

    #[test]
    fn ssz_serde_encode_decode_fluffy_epoch_accumulator() {
        // values sourced from: https://github.com/status-im/portal-spec-tests
        let epoch_acc_ssz = fs::read("./src/assets/test/fluffy_epoch_acc.bin").unwrap();
        let epoch_acc = EpochAccumulator::from_ssz_bytes(&epoch_acc_ssz).unwrap();
        assert_eq!(epoch_acc.len(), EPOCH_SIZE);
        assert_eq!(epoch_acc.as_ssz_bytes(), epoch_acc_ssz);
    }

    #[test]
    fn ssz_serde_encode_decode_ultralight_epoch_accumulator() {
        let epoch_acc_hex =
            fs::read_to_string("./src/assets/test/ultralight_testEpoch.hex").unwrap();
        let epoch_acc_ssz = hex::decode(epoch_acc_hex.strip_prefix("0x").unwrap()).unwrap();
        let epoch_acc = EpochAccumulator::from_ssz_bytes(&epoch_acc_ssz).unwrap();
        assert_eq!(epoch_acc.len(), EPOCH_SIZE);
        assert_eq!(epoch_acc.as_ssz_bytes(), epoch_acc_ssz);
    }
}
