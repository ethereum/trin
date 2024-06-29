use crate::e2s::{E2StoreFile, Entry};
use alloy_primitives::{B256, U256};
use alloy_rlp::Decodable;
use anyhow::ensure;
use ethportal_api::types::execution::{block_body::BlockBody, header::Header, receipts::Receipts};
use std::{
    fs,
    io::{Read, Write},
};

// <config-name>-<era-number>-<era-count>-<short-historical-root>.era
//
// era1 := Version | block-tuple* | other-entries* | Accumulator | BlockIndex
// block-tuple :=  CompressedHeader | CompressedBody | CompressedReceipts | TotalDifficulty
// -----
// Version            = { type: 0x3265, data: nil }
// CompressedHeader   = { type: 0x03,   data: snappyFramed(rlp(header)) }
// CompressedBody     = { type: 0x04,   data: snappyFramed(rlp(body)) }
// CompressedReceipts = { type: 0x05,   data: snappyFramed(rlp(receipts)) }
// TotalDifficulty    = { type: 0x06,   data: uint256(header.total_difficulty) }
// Accumulator        = { type: 0x07,   data: hash_tree_root(List(HeaderRecord, 8192)) }
// BlockIndex         = { type: 0x3266, data: block-index }

pub const BLOCK_TUPLE_COUNT: usize = 8192;
const ERA1_ENTRY_COUNT: usize = BLOCK_TUPLE_COUNT * 4 + 3;

pub struct Era1 {
    pub version: VersionEntry,
    pub block_tuples: Vec<BlockTuple>,
    pub accumulator: AccumulatorEntry,
    pub block_index: BlockIndexEntry,
}

impl Era1 {
    pub fn read_from_file(path: String) -> anyhow::Result<Self> {
        let buf = fs::read(path)?;
        Self::deserialize(&buf)
    }

    /// Function to iterate over block tuples in an era1 file
    /// this is useful for processing large era1 files without storing the entire
    /// deserialized era1 object in memory.
    pub fn iter_tuples(raw_era1: Vec<u8>) -> impl Iterator<Item = BlockTuple> {
        let file = E2StoreFile::deserialize(&raw_era1).expect("invalid era1 file");
        let block_index =
            BlockIndexEntry::try_from(file.entries.last().expect("missing block index entry"))
                .expect("invalid block index entry")
                .block_index;
        (0..block_index.count).map(move |i| {
            let mut entries: [Entry; 4] = Default::default();
            for (j, entry) in entries.iter_mut().enumerate() {
                file.entries[i as usize * 4 + j + 1].clone_into(entry);
            }
            BlockTuple::try_from(&entries).expect("invalid block tuple")
        })
    }

    pub fn get_tuple_by_index(raw_era1: &[u8], index: u64) -> BlockTuple {
        let file = E2StoreFile::deserialize(raw_era1).expect("invalid era1 file");
        let mut entries: [Entry; 4] = Default::default();
        for (j, entry) in entries.iter_mut().enumerate() {
            file.entries[index as usize * 4 + j + 1].clone_into(entry);
        }
        BlockTuple::try_from(&entries).expect("invalid block tuple")
    }

    pub fn deserialize(buf: &[u8]) -> anyhow::Result<Self> {
        let file = E2StoreFile::deserialize(buf)?;
        ensure!(
            // era1 file #0-1895 || era1 file #1896
            file.entries.len() == ERA1_ENTRY_COUNT || file.entries.len() == 21451,
            "invalid era1 file: incorrect entry count"
        );
        let version = VersionEntry::try_from(&file.entries[0])?;
        let block_index =
            BlockIndexEntry::try_from(file.entries.last().expect("missing block index entry"))?;
        let mut block_tuples = vec![];
        let block_tuple_count = block_index.block_index.count as usize;
        for count in 0..block_tuple_count {
            let mut entries: [Entry; 4] = Default::default();
            for (i, entry) in entries.iter_mut().enumerate() {
                *entry = file.entries[count * 4 + i + 1].clone();
            }
            let block_tuple = BlockTuple::try_from(&entries)?;
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

    #[allow(dead_code)]
    fn write(&self) -> anyhow::Result<Vec<u8>> {
        let mut entries: Vec<Entry> = vec![];
        let version_entry: Entry = self.version.clone().try_into()?;
        entries.push(version_entry);
        for block_tuple in &self.block_tuples {
            let block_tuple_entries: [Entry; 4] = block_tuple.clone().try_into()?;
            entries.extend_from_slice(&block_tuple_entries);
        }
        let accumulator_entry: Entry = self.accumulator.clone().try_into()?;
        entries.push(accumulator_entry);
        let block_index_entry: Entry = self.block_index.clone().try_into()?;
        entries.push(block_index_entry);
        let file = E2StoreFile { entries };
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

impl TryFrom<&[Entry; 4]> for BlockTuple {
    type Error = anyhow::Error;

    fn try_from(entries: &[Entry; 4]) -> anyhow::Result<Self> {
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

impl TryInto<[Entry; 4]> for BlockTuple {
    type Error = anyhow::Error;

    fn try_into(self) -> anyhow::Result<[Entry; 4]> {
        Ok([
            self.header.try_into()?,
            self.body.try_into()?,
            self.receipts.try_into()?,
            self.total_difficulty.try_into()?,
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionEntry {
    version: Entry,
}

impl TryFrom<&Entry> for VersionEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> anyhow::Result<Self> {
        ensure!(
            entry.header.type_ == 0x3265,
            "invalid version entry: incorrect header type"
        );
        ensure!(
            entry.header.length == 0,
            "invalid version entry: incorrect header length"
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid version entry: incorrect header reserved bytes"
        );
        ensure!(
            entry.value.is_empty(),
            "invalid version entry: non-empty value"
        );
        Ok(Self {
            version: entry.clone(),
        })
    }
}

impl TryInto<Entry> for VersionEntry {
    type Error = anyhow::Error;

    fn try_into(self) -> anyhow::Result<Entry> {
        Ok(self.version)
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct HeaderEntry {
    pub header: Header,
}

impl TryFrom<&Entry> for HeaderEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == 0x03,
            "invalid header entry: incorrect header type"
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid header entry: incorrect header reserved bytes"
        );
        let mut decoder = snap::read::FrameDecoder::new(&entry.value[..]);
        let mut buf: Vec<u8> = vec![];
        decoder.read_to_end(&mut buf)?;
        let header = Decodable::decode(&mut buf.as_slice())?;
        Ok(Self { header })
    }
}

impl TryInto<Entry> for HeaderEntry {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Entry, Self::Error> {
        let rlp_encoded = alloy_rlp::encode(self.header);
        let buf: Vec<u8> = vec![];
        let mut encoder = snap::write::FrameEncoder::new(buf);
        let _ = encoder.write(&rlp_encoded)?;
        let encoded = encoder.into_inner()?;
        Ok(Entry::new(0x03, encoded))
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
            entry.header.type_ == 0x04,
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
        let rlp_encoded = alloy_rlp::encode(self.body);
        let buf: Vec<u8> = vec![];
        let mut encoder = snap::write::FrameEncoder::new(buf);
        let _ = encoder.write(&rlp_encoded)?;
        let encoded = encoder.into_inner()?;
        Ok(Entry::new(0x04, encoded))
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
            entry.header.type_ == 0x05,
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
        let rlp_encoded = alloy_rlp::encode(&self.receipts);
        let buf: Vec<u8> = vec![];
        let mut encoder = snap::write::FrameEncoder::new(buf);
        let _ = encoder.write(&rlp_encoded)?;
        let encoded = encoder.into_inner()?;
        Ok(Entry::new(0x05, encoded))
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
            entry.header.type_ == 0x06,
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

impl TryInto<Entry> for TotalDifficultyEntry {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Entry, Self::Error> {
        Ok(Entry::new(0x06, self.total_difficulty.to_be_bytes_vec()))
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
            entry.header.type_ == 0x07,
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

impl TryInto<Entry> for AccumulatorEntry {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Entry, Self::Error> {
        let value = self.accumulator.as_slice().to_vec();
        Ok(Entry::new(0x07, value))
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
            entry.header.type_ == 0x3266,
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
        Ok(Entry::new(0x3266, encoded))
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

    #[rstest::rstest]
    #[case::era1("../test_assets/era1/mainnet-00000-5ec1ffb8.era1")]
    #[case::era1("../test_assets/era1/mainnet-00001-a5364e9a.era1")]
    // epoch #10 contains txs
    #[case::era1("../test_assets/era1/mainnet-00010-5f5d4516.era1")]
    // this is a test era1 file that has been amended for size purposes,
    // since era1 files that contain typed txs are quite large.
    // it was created by copying the `mainnet-01600-c6a9ee35.era1` file
    // - the first 10 block tuples are included, unchanged
    // - the following 8182 block tuples contain empty bodies and receipts
    #[case::era1("../test_assets/era1/test-mainnet-01600-xxxxxxxx.era1")]
    fn test_era1(#[case] path: &str) {
        let era1 = Era1::read_from_file(path.to_string()).unwrap();
        let actual = era1.write().unwrap();
        let expected = fs::read(path).unwrap();
        assert_eq!(expected, actual);
        let era1_raw_bytes = fs::read(path).unwrap();
        let _block_tuples: Vec<BlockTuple> = Era1::iter_tuples(era1_raw_bytes).collect();
    }

    #[rstest::rstest]
    #[case("../test_assets/era1/mainnet-00000-5ec1ffb8.era1", 0)]
    #[case("../test_assets/era1/mainnet-00001-a5364e9a.era1", 8192)]
    #[case("../test_assets/era1/mainnet-00010-5f5d4516.era1", 81920)]
    fn test_era1_index(#[case] path: &str, #[case] index: u64) {
        let era1 = Era1::read_from_file(path.to_string()).unwrap();
        assert_eq!(era1.block_index.block_index.starting_number, index);
    }
}
