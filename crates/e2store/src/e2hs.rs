use std::{
    fs,
    io::{Read, Write},
};

use alloy::rlp::Decodable;
use anyhow::ensure;
use ethportal_api::types::execution::{
    block_body::BlockBody, header_with_proof::HeaderWithProof, receipts::Receipts,
};
use ssz::{Decode, Encode};

use crate::{
    e2store::{
        memory::E2StoreMemory,
        types::{Entry, VersionEntry},
    },
    entry_types,
};

// <config-name>-<era-number>-<era-count>-<short-historical-root>.era
//
// e2hs := Version | block-tuple* | other-entries* | BlockIndex
// block-tuple :=  CompressedHeader | CompressedBody | CompressedReceipts
// -----
// Version            = { type: 0x6532, data: nil }
// CompressedHWP      = { type: 0x0301,   data: snappyFramed(ssz(header_with_proof)) }
// CompressedBody     = { type: 0x04,   data: snappyFramed(rlp(body)) }
// CompressedReceipts = { type: 0x05,   data: snappyFramed(rlp(receipts)) }
// BlockIndex         = { type: 0x6232, data: block-index }

pub const BLOCK_TUPLE_COUNT: usize = 8192;
const E2HS_ENTRY_COUNT: usize = BLOCK_TUPLE_COUNT * 3 + 2;

pub struct E2HS {
    pub version: VersionEntry,
    pub block_tuples: Vec<BlockTuple>,
    pub block_index: BlockIndexEntry,
}

impl E2HS {
    pub fn read_from_file(path: String) -> anyhow::Result<Self> {
        let buf = fs::read(path)?;
        Self::deserialize(&buf)
    }

    /// Function to iterate over block tuples in an e2hs file
    /// this is useful for processing large e2hs files without storing the entire
    /// deserialized e2hs object in memory.
    pub fn iter_tuples(raw_e2hs: Vec<u8>) -> impl Iterator<Item = BlockTuple> {
        let file = E2StoreMemory::deserialize(&raw_e2hs).expect("invalid e2hs file");
        let block_index =
            BlockIndexEntry::try_from(file.entries.last().expect("missing block index entry"))
                .expect("invalid block index entry")
                .block_index;
        (0..block_index.count).map(move |i| {
            let mut entries: [Entry; 3] = Default::default();
            for (j, entry) in entries.iter_mut().enumerate() {
                file.entries[i as usize * 3 + j + 1].clone_into(entry);
            }
            BlockTuple::try_from(&entries).expect("invalid block tuple")
        })
    }

    pub fn get_tuple_by_index(raw_e2hs: &[u8], index: u64) -> BlockTuple {
        let file = E2StoreMemory::deserialize(raw_e2hs).expect("invalid e2hs file");
        let mut entries: [Entry; 3] = Default::default();
        for (j, entry) in entries.iter_mut().enumerate() {
            file.entries[index as usize * 3 + j + 1].clone_into(entry);
        }
        BlockTuple::try_from(&entries).expect("invalid block tuple")
    }

    pub fn deserialize(buf: &[u8]) -> anyhow::Result<Self> {
        let file = E2StoreMemory::deserialize(buf)?;
        ensure!(
            file.entries.len() == E2HS_ENTRY_COUNT,
            format!(
                "invalid e2hs file found during deser: incorrect entry count: found {}, expected {}",
                file.entries.len(),
                E2HS_ENTRY_COUNT
            )
        );
        let version = VersionEntry::try_from(&file.entries[0])?;
        let block_index =
            BlockIndexEntry::try_from(file.entries.last().expect("missing block index entry"))?;
        let mut block_tuples = vec![];
        let block_tuple_count = block_index.block_index.count as usize;
        for count in 0..block_tuple_count {
            let mut entries: [Entry; 3] = Default::default();
            for (i, entry) in entries.iter_mut().enumerate() {
                *entry = file.entries[count * 3 + i + 1].clone();
            }
            let block_tuple = BlockTuple::try_from(&entries)?;
            block_tuples.push(block_tuple);
        }
        Ok(Self {
            version,
            block_tuples,
            block_index,
        })
    }

    pub fn write(&self) -> anyhow::Result<Vec<u8>> {
        let mut entries: Vec<Entry> = vec![];
        let version_entry: Entry = self.version.clone().into();
        entries.push(version_entry);
        for block_tuple in &self.block_tuples {
            let block_tuple_entries: [Entry; 3] = block_tuple.clone().try_into()?;
            entries.extend_from_slice(&block_tuple_entries);
        }
        let block_index_entry: Entry = self.block_index.clone().try_into()?;
        entries.push(block_index_entry);
        let file = E2StoreMemory { entries };
        ensure!(
            file.entries.len() == E2HS_ENTRY_COUNT,
            format!(
                "invalid e2hs file found during write: incorrect entry count: found {}, expected {}",
                file.entries.len(),
                E2HS_ENTRY_COUNT
            )
        );
        let file_length = file.length();
        let mut buf = vec![0; file_length];
        file.write(&mut buf)?;
        Ok(buf)
    }

    pub fn epoch_number_from_block_number(block_number: u64) -> u64 {
        block_number / (BLOCK_TUPLE_COUNT as u64)
    }

    pub fn epoch_number(&self) -> u64 {
        Self::epoch_number_from_block_number(self.block_index.block_index.starting_number)
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BlockTuple {
    pub header_with_proof: HeaderWithProofEntry,
    pub body: BodyEntry,
    pub receipts: ReceiptsEntry,
}

impl TryFrom<&[Entry; 3]> for BlockTuple {
    type Error = anyhow::Error;

    fn try_from(entries: &[Entry; 3]) -> anyhow::Result<Self> {
        let header_with_proof = HeaderWithProofEntry::try_from(&entries[0])?;
        let body = BodyEntry::try_from(&entries[1])?;
        let receipts = ReceiptsEntry::try_from(&entries[2])?;
        Ok(Self {
            header_with_proof,
            body,
            receipts,
        })
    }
}

impl TryInto<[Entry; 3]> for BlockTuple {
    type Error = anyhow::Error;

    fn try_into(self) -> anyhow::Result<[Entry; 3]> {
        Ok([
            self.header_with_proof.try_into()?,
            self.body.try_into()?,
            self.receipts.try_into()?,
        ])
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct HeaderWithProofEntry {
    pub header_with_proof: HeaderWithProof,
}

impl TryFrom<&Entry> for HeaderWithProofEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == entry_types::COMPRESSED_HEADER_WITH_PROOF,
            "invalid header entry: incorrect header type"
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid header entry: incorrect header reserved bytes"
        );
        let mut decoder = snap::read::FrameDecoder::new(&entry.value[..]);
        let mut buf: Vec<u8> = vec![];
        decoder.read_to_end(&mut buf)?;
        let header_with_proof = HeaderWithProof::from_ssz_bytes(&buf).map_err(|e| {
            anyhow::anyhow!("failed to decode header with proof from ssz bytes: {:?}", e)
        })?;
        Ok(Self { header_with_proof })
    }
}

impl TryFrom<HeaderWithProofEntry> for Entry {
    type Error = anyhow::Error;

    fn try_from(value: HeaderWithProofEntry) -> Result<Self, Self::Error> {
        let ssz_encoded = value.header_with_proof.as_ssz_bytes();
        let buf: Vec<u8> = vec![];
        let mut encoder = snap::write::FrameEncoder::new(buf);
        let _ = encoder.write(&ssz_encoded)?;
        let encoded = encoder.into_inner()?;
        Ok(Entry::new(
            entry_types::COMPRESSED_HEADER_WITH_PROOF,
            encoded,
        ))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BodyEntry {
    pub body: BlockBody,
}

impl TryFrom<&Entry> for BodyEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == entry_types::COMPRESSED_BODY,
            "invalid body entry: incorrect header type"
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid body entry: incorrect header reserved bytes"
        );
        let mut decoder = snap::read::FrameDecoder::new(&entry.value[..]);
        let mut buf: Vec<u8> = vec![];
        decoder.read_to_end(&mut buf)?;
        let body = Decodable::decode(&mut buf.as_slice())?;
        Ok(Self { body })
    }
}

impl TryInto<Entry> for BodyEntry {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Entry, Self::Error> {
        let rlp_encoded = alloy::rlp::encode(self.body);
        let buf: Vec<u8> = vec![];
        let mut encoder = snap::write::FrameEncoder::new(buf);
        let _ = encoder.write(&rlp_encoded)?;
        let encoded = encoder.into_inner()?;
        Ok(Entry::new(entry_types::COMPRESSED_BODY, encoded))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ReceiptsEntry {
    pub receipts: Receipts,
}

impl TryFrom<&Entry> for ReceiptsEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == entry_types::COMPRESSED_RECEIPTS,
            "invalid receipts entry: incorrect header type"
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid receipts entry: incorrect header reserved bytes"
        );
        let mut decoder = snap::read::FrameDecoder::new(&entry.value[..]);
        let mut buf: Vec<u8> = vec![];
        decoder.read_to_end(&mut buf)?;
        let receipts: Receipts = Decodable::decode(&mut buf.as_slice())?;
        Ok(Self { receipts })
    }
}

impl TryInto<Entry> for ReceiptsEntry {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Entry, Self::Error> {
        let rlp_encoded = alloy::rlp::encode(&self.receipts);
        let buf: Vec<u8> = vec![];
        let mut encoder = snap::write::FrameEncoder::new(buf);
        let _ = encoder.write(&rlp_encoded)?;
        let encoded = encoder.into_inner()?;
        Ok(Entry::new(entry_types::COMPRESSED_RECEIPTS, encoded))
    }
}

//   block-index := starting-number | index | index | index ... | count

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BlockIndexEntry {
    pub block_index: BlockIndex,
}

impl TryFrom<&Entry> for BlockIndexEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == entry_types::BLOCK_INDEX,
            "invalid block index entry: incorrect header type"
        );
        ensure!(
            entry.header.length == 65552,
            format!(
                "invalid block index entry: incorrect header length: found {}, expected {}",
                entry.header.length, 65552
            )
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid block index entry: incorrect header reserved bytes"
        );
        ensure!(
            entry.value.len() == 65552,
            "invalid block index entry: incorrect value length"
        );
        Ok(Self {
            block_index: BlockIndex::try_from(entry.clone())?,
        })
    }
}

impl TryInto<Entry> for BlockIndexEntry {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Entry, Self::Error> {
        let mut buf: Vec<u64> = vec![];
        buf.push(self.block_index.starting_number);
        buf.extend_from_slice(&self.block_index.indices);
        buf.push(self.block_index.count);
        let encoded = buf
            .iter()
            .flat_map(|i| i.to_le_bytes().to_vec())
            .collect::<Vec<u8>>();
        Ok(Entry::new(entry_types::BLOCK_INDEX, encoded))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BlockIndex {
    pub starting_number: u64,
    pub indices: Vec<u64>,
    pub count: u64,
}

impl TryFrom<Entry> for BlockIndex {
    type Error = anyhow::Error;

    fn try_from(entry: Entry) -> Result<Self, Self::Error> {
        let starting_number = u64::from_le_bytes(entry.value[0..8].try_into()?);
        let block_tuple_count = (entry.value.len() - 16) / 8;
        let mut indices = vec![0; block_tuple_count];
        for (i, index) in indices.iter_mut().enumerate() {
            *index = u64::from_le_bytes(entry.value[(i * 8 + 8)..(i * 8 + 16)].try_into()?);
        }
        let count = u64::from_le_bytes(
            entry.value[(block_tuple_count * 8 + 8)..(block_tuple_count * 8 + 16)].try_into()?,
        );
        Ok(Self {
            starting_number,
            indices,
            count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2store::types::Header;

    #[test]
    fn test_e2hs_round_trip() {
        let raw_e2hs = fs::read("../../test_assets/era1/mainnet-00000-93fc0269.e2hs").unwrap();
        let e2hs = E2HS::deserialize(&raw_e2hs).expect("failed to deserialize e2hs");
        let raw_e2hs2 = e2hs.write().expect("failed to serialize e2hs");
        assert_eq!(raw_e2hs, raw_e2hs2);
    }

    #[rstest::rstest]
    #[case(0)]
    #[case(1)]
    #[case(100)]
    #[case(8191)]
    fn test_e2hs_block_index(#[case] block_number: u64) {
        let raw_e2hs = fs::read("../../test_assets/era1/mainnet-00000-93fc0269.e2hs").unwrap();
        let block_tuple = E2HS::get_tuple_by_index(&raw_e2hs, block_number);
        assert_eq!(
            block_tuple
                .header_with_proof
                .header_with_proof
                .header
                .number,
            block_number
        );
    }

    #[test]
    fn test_e2hs_block_index_direct_access() {
        let raw_e2hs = fs::read("../../test_assets/era1/mainnet-00000-93fc0269.e2hs").unwrap();
        let file = E2StoreMemory::deserialize(&raw_e2hs).expect("invalid e2hs file");
        let block_index =
            BlockIndexEntry::try_from(file.entries.last().expect("missing block index entry"))
                .expect("invalid block index entry")
                .block_index;
        let index_100 = block_index.indices[100];
        let header_bytes = raw_e2hs
            .get((index_100 as usize)..(index_100 as usize + 8))
            .unwrap();
        let header = Header::deserialize(header_bytes).expect("invalid header");
        let hwp_length = header.length as u64;
        let hwp_bytes = raw_e2hs
            .get((index_100 as usize + 8)..(index_100 as usize + 8 + hwp_length as usize))
            .unwrap();
        let mut decoder = snap::read::FrameDecoder::new(hwp_bytes);
        let mut buf: Vec<u8> = vec![];
        decoder.read_to_end(&mut buf).unwrap();
        let header_with_proof = HeaderWithProof::from_ssz_bytes(&buf).unwrap();
        assert_eq!(header_with_proof.header.number, 100);
    }
}
