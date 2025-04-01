//! The format for storing history chain data snapshots.
//!
//! Filename:
//!
//! ```text
//! <config-name>-<era-number>-<short-hash>.e2hs
//! ```
//!
//! Type Definitions:
//!
//! ```text
//! e2hs := Version | block-tuple* | other-entries* | BlockIndex
//! block-tuple :=  CompressedHeader | CompressedBody | CompressedReceipts
//! -----
//! Version            = { type: 0x6532, data: nil }
//! CompressedHWP      = { type: 0x0301, data: snappyFramed(ssz(header_with_proof)) }
//! CompressedBody     = { type: 0x0400, data: snappyFramed(rlp(body)) }
//! CompressedReceipts = { type: 0x0500, data: snappyFramed(rlp(receipts)) }
//! BlockIndex         = { type: 0x6632, data: block-index }
//! ```
//!
//! E2HS files must each contain a contiguous sequence of 8192 blocks.
//! Full file spec can be found here:
//! https://github.com/eth-clients/e2store-format-specs/blob/main/formats/e2hs.md

use std::{
    fs,
    io::{Read, Write},
};

use anyhow::{anyhow, ensure};
use ethportal_api::types::execution::header_with_proof::HeaderWithProof;
use ssz::{Decode, Encode};

use crate::{
    e2store::{
        memory::E2StoreMemory,
        types::{Entry, VersionEntry},
    },
    entry_types,
    era1::{BlockIndex, BodyEntry, ReceiptsEntry},
};

pub const BLOCK_TUPLE_COUNT: usize = 8192;
const E2HS_ENTRY_COUNT: usize = BLOCK_TUPLE_COUNT * 3 + 2;

pub struct E2HS {
    pub version: VersionEntry,
    pub block_tuples: Vec<BlockTuple>,
    pub block_index: E2HSBlockIndexEntry,
}

impl E2HS {
    pub fn read_from_file(path: String) -> anyhow::Result<Self> {
        let buf = fs::read(path)?;
        Self::deserialize(&buf)
    }

    /// Function to iterate over block tuples in an e2hs file
    /// this is useful for processing large e2hs files without storing the entire
    /// deserialized e2hs object in memory.
    pub fn iter_tuples(raw_e2hs: Vec<u8>) -> anyhow::Result<impl Iterator<Item = BlockTuple>> {
        let file = E2StoreMemory::deserialize(&raw_e2hs)?;
        let last_entry = file.entries.last().ok_or(anyhow!(
            "invalid e2hs file found during iter: missing block index entry"
        ))?;
        let block_index = E2HSBlockIndexEntry::try_from(last_entry)?.block_index;
        Ok((0..block_index.count).map(move |i| {
            BlockTuple::try_from(&file.entries[i as usize * 3 + 1..i as usize * 3 + 4])
                .expect("invalid block tuple")
        }))
    }

    pub fn get_tuple_by_index(raw_e2hs: &[u8], index: usize) -> anyhow::Result<BlockTuple> {
        let file = E2StoreMemory::deserialize(raw_e2hs)?;
        BlockTuple::try_from(&file.entries[index * 3 + 1..index * 3 + 4])
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
        let last_entry = file.entries.last().ok_or(anyhow!(
            "invalid e2hs file found during iter: missing block index entry"
        ))?;
        let block_index = E2HSBlockIndexEntry::try_from(last_entry)?;
        let mut block_tuples = vec![];
        let block_tuple_count = block_index.block_index.count as usize;
        for count in 0..block_tuple_count {
            let block_tuple = BlockTuple::try_from(&file.entries[count * 3 + 1..count * 3 + 4])?;
            block_tuples.push(block_tuple);
        }
        Ok(Self {
            version,
            block_tuples,
            block_index,
        })
    }

    pub fn write(&self) -> anyhow::Result<Vec<u8>> {
        let mut entries: Vec<Entry> = Vec::with_capacity(E2HS_ENTRY_COUNT);
        let version_entry = Entry::from(&self.version);
        entries.push(version_entry);
        for block_tuple in &self.block_tuples {
            let block_tuple_entries = <[Entry; 3]>::try_from(block_tuple)?;
            entries.extend(block_tuple_entries);
        }
        let block_index_entry = Entry::from(&self.block_index);
        entries.push(block_index_entry);
        ensure!(
            entries.len() == E2HS_ENTRY_COUNT,
            format!(
                "invalid e2hs file found during write: incorrect entry count: found {}, expected {}",
                entries.len(),
                E2HS_ENTRY_COUNT
            )
        );
        let file = E2StoreMemory { entries };
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

impl TryFrom<&[Entry]> for BlockTuple {
    type Error = anyhow::Error;

    fn try_from(entries: &[Entry]) -> Result<Self, Self::Error> {
        ensure!(
            entries.len() == 3,
            format!(
                "invalid block tuple entry: incorrect entry count: found {}, expected 3",
                entries.len()
            )
        );
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

impl TryFrom<&BlockTuple> for [Entry; 3] {
    type Error = anyhow::Error;

    fn try_from(value: &BlockTuple) -> Result<Self, Self::Error> {
        let header_with_proof = Entry::try_from(&value.header_with_proof)?;
        let body = Entry::try_from(&value.body)?;
        let receipts = Entry::try_from(&value.receipts)?;
        Ok([header_with_proof, body, receipts])
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

impl TryFrom<&HeaderWithProofEntry> for Entry {
    type Error = std::io::Error;

    fn try_from(value: &HeaderWithProofEntry) -> Result<Self, Self::Error> {
        let ssz_encoded = value.header_with_proof.as_ssz_bytes();
        let buf: Vec<u8> = vec![];
        let mut encoder = snap::write::FrameEncoder::new(buf);
        let _ = encoder.write(&ssz_encoded)?;
        let encoded = encoder.into_inner().map_err(|e| e.into_error())?;
        Ok(Entry::new(
            entry_types::COMPRESSED_HEADER_WITH_PROOF,
            encoded,
        ))
    }
}

//   block-index := starting-number | index | index | index ... | count

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct E2HSBlockIndexEntry {
    pub block_index: BlockIndex,
}

impl TryFrom<&Entry> for E2HSBlockIndexEntry {
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
            block_index: BlockIndex::try_from(entry)?,
        })
    }
}

impl From<&E2HSBlockIndexEntry> for Entry {
    fn from(value: &E2HSBlockIndexEntry) -> Self {
        let mut buf: Vec<u64> = vec![];
        buf.push(value.block_index.starting_number);
        buf.extend_from_slice(&value.block_index.indices);
        buf.push(value.block_index.count);
        let encoded = buf
            .iter()
            .flat_map(|i| i.to_le_bytes().to_vec())
            .collect::<Vec<u8>>();
        Self::new(entry_types::BLOCK_INDEX, encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2store::types::Header;

    #[test]
    fn test_e2hs_round_trip() {
        let raw_e2hs = fs::read("../../test_assets/era1/mainnet-00000-a6860fef.e2hs").unwrap();
        let e2hs = E2HS::deserialize(&raw_e2hs).expect("failed to deserialize e2hs");
        let raw_e2hs2 = e2hs.write().expect("failed to serialize e2hs");
        assert_eq!(raw_e2hs, raw_e2hs2);
    }

    #[rstest::rstest]
    #[case(0)]
    #[case(1)]
    #[case(100)]
    #[case(8191)]
    fn test_e2hs_block_index(#[case] block_number: usize) {
        let raw_e2hs = fs::read("../../test_assets/era1/mainnet-00000-a6860fef.e2hs").unwrap();
        let block_tuple = E2HS::get_tuple_by_index(&raw_e2hs, block_number).unwrap();
        assert_eq!(
            block_tuple
                .header_with_proof
                .header_with_proof
                .header
                .number,
            block_number as u64
        );
    }

    #[rstest::rstest]
    #[case(0)]
    #[case(1)]
    #[case(100)]
    #[case(8191)]
    fn test_e2hs_block_index_direct_access(#[case] block_number: u64) {
        let raw_e2hs = fs::read("../../test_assets/era1/mainnet-00000-a6860fef.e2hs").unwrap();
        let file = E2StoreMemory::deserialize(&raw_e2hs).expect("invalid e2hs file");
        let block_index =
            E2HSBlockIndexEntry::try_from(file.entries.last().expect("missing block index entry"))
                .expect("invalid block index entry")
                .block_index;
        let index = block_index.indices[block_number as usize];
        let header_bytes = raw_e2hs
            .get((index as usize)..(index as usize + 8))
            .unwrap();
        let header = Header::deserialize(header_bytes).expect("invalid header");
        let hwp_length = header.length as u64;
        let hwp_bytes = raw_e2hs
            .get((index as usize + 8)..(index as usize + 8 + hwp_length as usize))
            .unwrap();
        let mut decoder = snap::read::FrameDecoder::new(hwp_bytes);
        let mut buf: Vec<u8> = vec![];
        decoder.read_to_end(&mut buf).unwrap();
        let header_with_proof = HeaderWithProof::from_ssz_bytes(&buf).unwrap();
        assert_eq!(header_with_proof.header.number, block_number);
    }
}
