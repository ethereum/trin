use std::{
    fs,
    io::{Read, Write},
};

use alloy::{
    primitives::{B256, U256},
    rlp::Decodable,
};
use anyhow::{anyhow, ensure};
use ethportal_api::types::execution::{block_body::BlockBody, receipts::Receipts};

use crate::{
    e2store::{
        memory::E2StoreMemory,
        types::{Entry, VersionEntry},
    },
    entry_types,
    types::HeaderEntry,
};

// <config-name>-<era-number>-<era-count>-<short-historical-root>.era
//
// era1 := Version | block-tuple* | other-entries* | Accumulator | BlockIndex
// block-tuple :=  CompressedHeader | CompressedBody | CompressedReceipts | TotalDifficulty
// -----
// Version            = { type: 0x6532, data: nil }
// CompressedHeader   = { type: 0x0300,   data: snappyFramed(rlp(header)) }
// CompressedBody     = { type: 0x0400,   data: snappyFramed(rlp(body)) }
// CompressedReceipts = { type: 0x0500,   data: snappyFramed(rlp(receipts)) }
// TotalDifficulty    = { type: 0x0600,   data: uint256(header.total_difficulty) }
// Accumulator        = { type: 0x0700,   data: hash_tree_root(List(HeaderRecord, 8192)) }
// BlockIndex         = { type: 0x6632, data: block-index }

pub const BLOCK_TUPLE_COUNT: usize = 8192;
const ERA1_ENTRY_COUNT: usize = BLOCK_TUPLE_COUNT * 4 + 3;

pub struct Era1 {
    pub version: VersionEntry,
    pub block_tuples: Vec<BlockTuple>,
    pub accumulator: AccumulatorEntry,
    pub block_index: Era1BlockIndexEntry,
}

impl Era1 {
    pub fn read_from_file(path: String) -> anyhow::Result<Self> {
        let buf = fs::read(path)?;
        Self::deserialize(&buf)
    }

    /// Function to iterate over block tuples in an era1 file
    /// this is useful for processing large era1 files without storing the entire
    /// deserialized era1 object in memory.
    pub fn iter_tuples(raw_era1: &[u8]) -> anyhow::Result<impl Iterator<Item = BlockTuple>> {
        let file = E2StoreMemory::deserialize(raw_era1)?;
        let block_index = Era1BlockIndexEntry::try_from(
            file.entries
                .last()
                .ok_or(anyhow!("missing block index entry"))?,
        )
        .expect("invalid block index entry")
        .block_index;
        Ok((0..block_index.count).map(move |i| {
            BlockTuple::try_from(&file.entries[i as usize * 4 + 1..i as usize * 4 + 5])
                .expect("invalid block tuple")
        }))
    }

    pub fn deserialize(buf: &[u8]) -> anyhow::Result<Self> {
        let file = E2StoreMemory::deserialize(buf)?;
        ensure!(
            // era1 file #0-1895 || era1 file #1896
            file.entries.len() == ERA1_ENTRY_COUNT || file.entries.len() == 21451,
            "invalid era1 file: incorrect entry count"
        );
        let version = VersionEntry::try_from(&file.entries[0])?;
        let block_index =
            Era1BlockIndexEntry::try_from(file.entries.last().expect("missing block index entry"))?;
        let mut block_tuples = vec![];
        let block_tuple_count = block_index.block_index.count as usize;
        for count in 0..block_tuple_count {
            let block_tuple = BlockTuple::try_from(&file.entries[count * 4 + 1..count * 4 + 5])?;
            block_tuples.push(block_tuple);
        }
        let accumulator_index = (block_tuple_count * 4) + 1;
        let accumulator = AccumulatorEntry::try_from(&file.entries[accumulator_index])?;
        Ok(Self {
            version,
            block_tuples,
            accumulator,
            block_index,
        })
    }

    pub fn write(&self) -> anyhow::Result<Vec<u8>> {
        let mut entries: Vec<Entry> = vec![];
        let version_entry = Entry::from(&self.version);
        entries.push(version_entry);
        for block_tuple in &self.block_tuples {
            let block_tuple_entries = <[Entry; 4]>::try_from(block_tuple)?;
            entries.extend_from_slice(&block_tuple_entries);
        }
        let accumulator_entry = Entry::from(&self.accumulator);
        entries.push(accumulator_entry);
        let block_index_entry = Entry::from(&self.block_index);
        entries.push(block_index_entry);
        let file = E2StoreMemory { entries };
        ensure!(
            // era1 file #0-1895 || era1 file #1896
            file.entries.len() == ERA1_ENTRY_COUNT || file.entries.len() == 21451,
            "invalid era1 file: incorrect entry count"
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
    pub header: HeaderEntry,
    pub body: BodyEntry,
    pub receipts: ReceiptsEntry,
    pub total_difficulty: TotalDifficultyEntry,
}

impl TryFrom<&[Entry]> for BlockTuple {
    type Error = anyhow::Error;

    fn try_from(entries: &[Entry]) -> Result<Self, Self::Error> {
        ensure!(
            entries.len() == 4,
            "invalid block tuple: incorrect number of entries, found {} expected 4",
            entries.len()
        );
        let header = HeaderEntry::try_from(&entries[0])?;
        let body = BodyEntry::try_from(&entries[1])?;
        let receipts = ReceiptsEntry::try_from(&entries[2])?;
        let total_difficulty = TotalDifficultyEntry::try_from(&entries[3])?;
        Ok(Self {
            header,
            body,
            receipts,
            total_difficulty,
        })
    }
}

impl TryFrom<&BlockTuple> for [Entry; 4] {
    type Error = anyhow::Error;

    fn try_from(value: &BlockTuple) -> Result<Self, Self::Error> {
        let header = Entry::try_from(&value.header)?;
        let body = Entry::try_from(&value.body)?;
        let receipts = Entry::try_from(&value.receipts)?;
        let total_difficulty = Entry::from(&value.total_difficulty);
        Ok([header, body, receipts, total_difficulty])
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

impl TryFrom<&BodyEntry> for Entry {
    type Error = std::io::Error;

    fn try_from(value: &BodyEntry) -> Result<Self, Self::Error> {
        let rlp_encoded = alloy::rlp::encode(&value.body);
        let buf: Vec<u8> = vec![];
        let mut encoder = snap::write::FrameEncoder::new(buf);
        let _ = encoder.write(&rlp_encoded)?;
        let encoded = encoder.into_inner().map_err(|e| e.into_error())?;
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

impl TryFrom<&ReceiptsEntry> for Entry {
    type Error = std::io::Error;

    fn try_from(value: &ReceiptsEntry) -> Result<Self, Self::Error> {
        let rlp_encoded = alloy::rlp::encode(&value.receipts);
        let buf: Vec<u8> = vec![];
        let mut encoder = snap::write::FrameEncoder::new(buf);
        let _ = encoder.write(&rlp_encoded)?;
        let encoded = encoder.into_inner().map_err(|e| e.into_error())?;
        Ok(Entry::new(entry_types::COMPRESSED_RECEIPTS, encoded))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct TotalDifficultyEntry {
    total_difficulty: U256,
}

impl TryFrom<&Entry> for TotalDifficultyEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == entry_types::TOTAL_DIFFICULTY,
            "invalid total difficulty entry: incorrect header type"
        );
        ensure!(
            entry.header.length == 32,
            "invalid total difficulty entry: incorrect header length"
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid total difficulty entry: incorrect header reserved bytes"
        );
        ensure!(
            entry.value.len() == 32,
            "invalid total difficulty entry: incorrect value length"
        );
        let total_difficulty = U256::from_be_slice(entry.value.as_slice());
        Ok(Self { total_difficulty })
    }
}

impl From<&TotalDifficultyEntry> for Entry {
    fn from(value: &TotalDifficultyEntry) -> Self {
        let value = value.total_difficulty.to_be_bytes_vec();
        Entry::new(entry_types::TOTAL_DIFFICULTY, value)
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct AccumulatorEntry {
    accumulator: B256,
}

impl TryFrom<&Entry> for AccumulatorEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == entry_types::ACCUMULATOR,
            "invalid accumulator entry: incorrect header type"
        );
        ensure!(
            entry.header.length == 32,
            "invalid accumulator entry: incorrect header length"
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid accumulator entry: incorrect header reserved bytes"
        );
        ensure!(
            entry.value.len() == 32,
            "invalid accumulator entry: incorrect value length"
        );
        let accumulator = B256::from_slice(&entry.value);
        Ok(Self { accumulator })
    }
}

impl From<&AccumulatorEntry> for Entry {
    fn from(value: &AccumulatorEntry) -> Entry {
        let value = value.accumulator.as_slice().to_vec();
        Entry::new(entry_types::ACCUMULATOR, value)
    }
}

//   block-index := starting-number | index | index | index ... | count

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Era1BlockIndexEntry {
    pub block_index: BlockIndex,
}

impl TryFrom<&Entry> for Era1BlockIndexEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == entry_types::BLOCK_INDEX,
            "invalid block index entry: incorrect header type"
        );
        ensure!(
            // era1 file #0-1895 || era1 file #1896
            entry.header.length == 65552 || entry.header.length == 42912,
            "invalid block index entry: incorrect header length"
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid block index entry: incorrect header reserved bytes"
        );
        ensure!(
            // era1 file #0-1895 || era1 file #1896
            entry.value.len() == 65552 || entry.value.len() == 42912,
            "invalid block index entry: incorrect value length"
        );
        Ok(Self {
            block_index: BlockIndex::try_from(entry)?,
        })
    }
}

impl From<&Era1BlockIndexEntry> for Entry {
    fn from(value: &Era1BlockIndexEntry) -> Entry {
        let mut buf: Vec<u64> = vec![];
        buf.push(value.block_index.starting_number);
        buf.extend_from_slice(&value.block_index.indices);
        buf.push(value.block_index.count);
        let encoded = buf
            .iter()
            .flat_map(|i| i.to_le_bytes().to_vec())
            .collect::<Vec<u8>>();
        Entry::new(entry_types::BLOCK_INDEX, encoded)
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BlockIndex {
    pub starting_number: u64,
    pub indices: Vec<u64>,
    pub count: u64,
}

impl TryFrom<&Entry> for BlockIndex {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
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

    #[rstest::rstest]
    #[case::era1("../../test_assets/era1/mainnet-00000-5ec1ffb8.era1")]
    #[case::era1("../../test_assets/era1/mainnet-00001-a5364e9a.era1")]
    // epoch #10 contains txs
    #[case::era1("../../test_assets/era1/mainnet-00010-5f5d4516.era1")]
    // this is a test era1 file that has been amended for size purposes,
    // since era1 files that contain typed txs are quite large.
    // it was created by copying the `mainnet-01600-c6a9ee35.era1` file
    // - the first 10 block tuples are included, unchanged
    // - the following 8182 block tuples contain empty bodies and receipts
    #[case::era1("../../test_assets/era1/test-mainnet-01600-xxxxxxxx.era1")]
    fn test_era1(#[case] path: &str) {
        let era1 = Era1::read_from_file(path.to_string()).unwrap();
        let actual = era1.write().unwrap();
        let expected = fs::read(path).unwrap();
        assert_eq!(expected, actual);
        let era1_raw_bytes = fs::read(path).unwrap();
        let _block_tuples: Vec<BlockTuple> = Era1::iter_tuples(&era1_raw_bytes).unwrap().collect();
    }

    #[rstest::rstest]
    #[case("../../test_assets/era1/mainnet-00000-5ec1ffb8.era1", 0)]
    #[case("../../test_assets/era1/mainnet-00001-a5364e9a.era1", 8192)]
    #[case("../../test_assets/era1/mainnet-00010-5f5d4516.era1", 81920)]
    fn test_era1_index(#[case] path: &str, #[case] index: u64) {
        let era1 = Era1::read_from_file(path.to_string()).unwrap();
        assert_eq!(era1.block_index.block_index.starting_number, index);
    }
}
