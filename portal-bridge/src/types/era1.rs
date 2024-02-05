use crate::types::e2s::{Entry, E2storeFile};
use anyhow::ensure;
use ethereum_types::{H256, U256};
use ethportal_api::types::execution::{
    block_body::BlockBody,
    header::Header,
    receipts::{LegacyReceipt, Receipt, Receipts},
};
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

const ERA1_ENTRY_COUNT: usize = 8192 * 4 + 3;

#[allow(dead_code)]
struct Era1 {
    version: VersionEntry,
    block_tuples: Vec<BlockTuple>,
    accumulator: AccumulatorEntry,
    block_index: BlockIndexEntry,
}

#[allow(dead_code)]
impl Era1 {
    fn read_from_file(path: String) -> anyhow::Result<Self> {
        let buf = fs::read(path)?;
        Self::read(&buf)
    }

    fn read(buf: &[u8]) -> anyhow::Result<Self> {
        let file = E2storeFile::read(buf)?;
        ensure!(
            file.entries.len() == ERA1_ENTRY_COUNT,
            "invalid era1 file: incorrect entry count"
        );
        let version = VersionEntry::try_from(&file.entries[0])?;
        let mut block_tuples = vec![];
        for count in 0..8192 {
            let mut entries: [Entry; 4] = Default::default();
            for (i, entry) in entries.iter_mut().enumerate() {
                *entry = file.entries[count * 4 + i + 1].clone();
            }
            let block_tuple = BlockTuple::try_from(&entries)?;
            block_tuples.push(block_tuple);
        }
        let accumulator = AccumulatorEntry::try_from(&file.entries[32769])?;
        let block_index = BlockIndexEntry::try_from(&file.entries[32770])?;
        Ok(Self {
            version,
            block_tuples,
            accumulator,
            block_index,
        })
    }

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
        let file = E2storeFile { entries };
        ensure!(
            file.entries.len() == ERA1_ENTRY_COUNT,
            "invalid era1 file: incorrect entry count"
        );
        let file_length = file.length();
        let mut buf = vec![0; file_length];
        file.write(&mut buf)?;
        Ok(buf)
    }
}

#[allow(dead_code)]
#[derive(Clone, Eq, PartialEq, Debug)]
struct BlockTuple {
    header: HeaderEntry,
    body: BodyEntry,
    receipts: ReceiptsEntry,
    total_difficulty: TotalDifficultyEntry,
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
struct VersionEntry {
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
struct HeaderEntry {
    header: Header,
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
        let header = rlp::decode(&buf)?;
        Ok(Self { header })
    }
}

impl TryInto<Entry> for HeaderEntry {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Entry, Self::Error> {
        let rlp_encoded = rlp::encode(&self.header).to_vec();
        let buf: Vec<u8> = vec![];
        let mut encoder = snap::write::FrameEncoder::new(buf);
        let _ = encoder.write(&rlp_encoded)?;
        let encoded = encoder.into_inner()?;
        Ok(Entry::new(0x03, encoded))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
struct BodyEntry {
    body: BlockBody,
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
        let body = rlp::decode(&buf)?;
        Ok(Self { body })
    }
}

impl TryInto<Entry> for BodyEntry {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Entry, Self::Error> {
        let rlp_encoded = rlp::encode(&self.body).to_vec();
        let buf: Vec<u8> = vec![];
        let mut encoder = snap::write::FrameEncoder::new(buf);
        let _ = encoder.write(&rlp_encoded)?;
        let encoded = encoder.into_inner()?;
        Ok(Entry::new(0x04, encoded))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
struct ReceiptsEntry {
    receipts: Receipts,
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
        let encoded_receipts: Vec<LegacyReceipt> = rlp::decode_list(&buf);
        let receipt_list = encoded_receipts
            .iter()
            .map(|r| Receipt::Legacy(r.clone()))
            .collect();
        let receipts = Receipts { receipt_list };
        Ok(Self { receipts })
    }
}

impl TryInto<Entry> for ReceiptsEntry {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Entry, Self::Error> {
        let rlp_encoded = rlp::encode(&self.receipts).to_vec();
        let buf: Vec<u8> = vec![];
        let mut encoder = snap::write::FrameEncoder::new(buf);
        let _ = encoder.write(&rlp_encoded)?;
        let encoded = encoder.into_inner()?;
        Ok(Entry::new(0x05, encoded))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
struct TotalDifficultyEntry {
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
        let total_difficulty = U256::from_big_endian(&entry.value);
        Ok(Self { total_difficulty })
    }
}

impl TryInto<Entry> for TotalDifficultyEntry {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Entry, Self::Error> {
        let mut value = [0u8; 32];
        self.total_difficulty.to_big_endian(&mut value);
        Ok(Entry::new(0x06, value.to_vec()))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
struct AccumulatorEntry {
    accumulator: H256,
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
        let accumulator = H256::from_slice(&entry.value);
        Ok(Self { accumulator })
    }
}

impl TryInto<Entry> for AccumulatorEntry {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Entry, Self::Error> {
        let value = self.accumulator.as_bytes().to_vec();
        Ok(Entry::new(0x07, value))
    }
}

//   block-index := starting-number | index | index | index ... | count

#[derive(Clone, Eq, PartialEq, Debug)]
struct BlockIndexEntry {
    block_index: BlockIndex,
}

impl TryFrom<&Entry> for BlockIndexEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == 0x3266,
            "invalid block index entry: incorrect header type"
        );
        ensure!(
            entry.header.length == 65552,
            "invalid block index entry: incorrect header length"
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
        Ok(Entry::new(0x3266, encoded))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
struct BlockIndex {
    starting_number: u64,
    indices: [u64; 8192],
    count: u64,
}

impl TryFrom<Entry> for BlockIndex {
    type Error = anyhow::Error;

    fn try_from(entry: Entry) -> Result<Self, Self::Error> {
        let starting_number = u64::from_le_bytes(entry.value[0..8].try_into()?);
        let mut indices = [0u64; 8192];
        for (i, index) in indices.iter_mut().enumerate() {
            *index = u64::from_le_bytes(entry.value[(i * 8 + 8)..(i * 8 + 16)].try_into()?);
        }
        let count = u64::from_le_bytes(entry.value[(8192 * 8 + 8)..(8192 * 8 + 16)].try_into()?);
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
    fn test_era1(#[case] path: &str) {
        let era1 = Era1::read_from_file(path.to_string()).unwrap();
        let actual = era1.write().unwrap();
        let expected = fs::read(path).unwrap();
        assert_eq!(expected, actual);
    }
}
