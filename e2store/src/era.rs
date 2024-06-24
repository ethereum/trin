use crate::{
    e2s::{E2StoreFile, Entry},
    era1::VersionEntry,
};
use anyhow::{anyhow, ensure};
use ethportal_api::consensus::{
    beacon_block::SignedBeaconBlock, beacon_state::BeaconState, fork::ForkName,
};
use ssz::Encode;
use std::{
    fs,
    io::{Read, Write},
};

const SLOTS_PER_HISTORICAL_ROOT: usize = 8192;

/// group := Version | block* | era-state | other-entries* | slot-index(block)? | slot-index(state)
/// block := CompressedSignedBeaconBlock
/// era-state := CompressedBeaconState
/// slot-index-block := starting-slot | index | index | index ... | count
/// slot-index-state := starting-slot | index | 1
#[derive(Clone, PartialEq, Debug)]
pub struct Era {
    pub version: VersionEntry,
    pub blocks: Vec<CompressedSignedBeaconBlock>,
    pub era_state: CompressedBeaconState,
    pub slot_index_block: SlotIndexBlockEntry,
    pub slot_index_state: SlotIndexStateEntry,
}

impl Era {
    pub fn read_from_file(file_path: &str) -> Result<Self, anyhow::Error> {
        let buf = fs::read(file_path)?;
        Self::deserialize(&buf)
    }

    pub fn read_beacon_state_from_file(file_path: &str) -> Result<BeaconState, anyhow::Error> {
        let buf = fs::read(file_path)?;
        Self::deserialize_to_beacon_state(&buf)
    }

    pub fn deserialize(buf: &[u8]) -> anyhow::Result<Self> {
        let file = E2StoreFile::deserialize(buf)?;
        let version = VersionEntry::try_from(&file.entries[0])?;
        let entries_length = file.entries.len();
        let mut blocks = vec![];
        // Iterate over the block entries. Skip the first and last 3 entries.
        for idx in 1..entries_length - 4 {
            let entry: Entry = file.entries[idx].clone();
            let beacon_block = CompressedSignedBeaconBlock::try_from(&entry)?;
            blocks.push(beacon_block);
        }
        let era_state = CompressedBeaconState::try_from(&file.entries[entries_length - 3])?;
        let slot_index_block = SlotIndexBlockEntry::try_from(&file.entries[entries_length - 2])?;
        let slot_index_state = SlotIndexStateEntry::try_from(&file.entries[entries_length - 1])?;

        Ok(Self {
            version,
            blocks,
            era_state,
            slot_index_block,
            slot_index_state,
        })
    }

    /// Deserialize the `BeaconState` from the `Era` file.
    pub fn deserialize_to_beacon_state(buf: &[u8]) -> anyhow::Result<BeaconState> {
        let file = E2StoreFile::deserialize(buf)?;
        // The compressed `BeaconState` is the second to last entry in the file.
        let era_state = CompressedBeaconState::try_from(&file.entries[file.entries.len() - 3])?;
        Ok(era_state.state)
    }

    #[allow(dead_code)]
    fn write(&self) -> anyhow::Result<Vec<u8>> {
        let mut entries: Vec<Entry> = vec![];
        let version_entry: Entry = self.version.clone().try_into()?;
        entries.push(version_entry);
        for block in &self.blocks {
            let block_entry: Entry = block.clone().try_into()?;
            entries.push(block_entry);
        }
        let era_state_entry: Entry = self.era_state.clone().try_into()?;
        entries.push(era_state_entry);
        let slot_index_block_entry: Entry = self.slot_index_block.clone().try_into()?;
        entries.push(slot_index_block_entry);
        let slot_index_state_entry: Entry = self.slot_index_state.clone().try_into()?;
        entries.push(slot_index_state_entry);
        let file = E2StoreFile { entries };

        let file_length = file.length();
        let mut buf = vec![0; file_length];
        file.write(&mut buf)?;
        Ok(buf)
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct CompressedSignedBeaconBlock {
    pub block: SignedBeaconBlock,
}

impl TryFrom<&Entry> for CompressedSignedBeaconBlock {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == 0x01,
            "invalid compressed signed beacon block entry: incorrect header type"
        );

        let mut decoder = snap::read::FrameDecoder::new(&entry.value[..]);
        let mut buf: Vec<u8> = vec![];
        decoder.read_to_end(&mut buf)?;

        let block = SignedBeaconBlock::from_ssz_bytes(&buf, ForkName::Bellatrix)
            .map_err(|_| anyhow!("Unable to ssz decode beacon block body"))?;
        Ok(Self { block })
    }
}

impl TryInto<Entry> for CompressedSignedBeaconBlock {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Entry, Self::Error> {
        let ssz_encoded = self.block.as_ssz_bytes();
        let buf: Vec<u8> = vec![];
        let mut snappy_encoder = snap::write::FrameEncoder::new(buf);
        let _ = snappy_encoder.write(&ssz_encoded)?;
        let snappy_encoded = snappy_encoder.into_inner()?;

        let header = 0x01;
        Ok(Entry::new(header, snappy_encoded))
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct CompressedBeaconState {
    pub state: BeaconState,
}

impl TryFrom<&Entry> for CompressedBeaconState {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == 0x02,
            "invalid compressed beacon state entry: incorrect header type"
        );

        let mut decoder = snap::read::FrameDecoder::new(&entry.value[..]);
        let mut buf: Vec<u8> = vec![];
        decoder.read_to_end(&mut buf)?;

        let state = BeaconState::from_ssz_bytes(&buf, ForkName::Bellatrix)
            .map_err(|_| anyhow!("Unable to decode beacon state from ssz bytes"))?;
        Ok(Self { state })
    }
}

impl TryInto<Entry> for CompressedBeaconState {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Entry, Self::Error> {
        let ssz_encoded = self.state.as_ssz_bytes();
        let buf: Vec<u8> = vec![];
        let mut snappy_encoder = snap::write::FrameEncoder::new(buf);
        let _ = snappy_encoder.write(&ssz_encoded)?;
        let snappy_encoded = snappy_encoder.into_inner()?;

        let header = 0x02;
        Ok(Entry::new(header, snappy_encoded))
    }
}

// slot-index := starting-slot | index | index | index ... | count
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SlotIndexBlockEntry {
    pub slot_index: SlotIndexBlock,
}

impl TryFrom<&Entry> for SlotIndexBlockEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == 0x3269,
            "invalid slot index entry: incorrect header type"
        );
        ensure!(
            entry.header.length == 65552,
            "invalid slot index entry: incorrect header length"
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid slot index entry: incorrect header reserved bytes"
        );
        ensure!(
            entry.value.len() == 65552,
            "invalid slot index entry: incorrect value length"
        );
        Ok(Self {
            slot_index: SlotIndexBlock::try_from(entry.clone())?,
        })
    }
}

impl TryInto<Entry> for SlotIndexBlockEntry {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Entry, Self::Error> {
        let mut buf: Vec<u64> = vec![];
        buf.push(self.slot_index.starting_slot);
        buf.extend_from_slice(&self.slot_index.indices);
        buf.push(self.slot_index.count);
        let encoded = buf
            .iter()
            .flat_map(|i| i.to_le_bytes().to_vec())
            .collect::<Vec<u8>>();
        Ok(Entry::new(0x3269, encoded))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SlotIndexBlock {
    pub starting_slot: u64,
    pub indices: [u64; SLOTS_PER_HISTORICAL_ROOT],
    pub count: u64,
}

impl TryFrom<Entry> for SlotIndexBlock {
    type Error = anyhow::Error;

    fn try_from(entry: Entry) -> Result<Self, Self::Error> {
        let starting_slot = u64::from_le_bytes(entry.value[0..8].try_into()?);
        let mut indices = [0u64; SLOTS_PER_HISTORICAL_ROOT];
        for (i, index) in indices.iter_mut().enumerate() {
            *index = u64::from_le_bytes(entry.value[(i * 8 + 8)..(i * 8 + 16)].try_into()?);
        }
        let count = u64::from_le_bytes(
            entry.value[(SLOTS_PER_HISTORICAL_ROOT * 8 + 8)..(SLOTS_PER_HISTORICAL_ROOT * 8 + 16)]
                .try_into()?,
        );
        Ok(Self {
            starting_slot,
            indices,
            count,
        })
    }
}

// slot-index := starting-slot | index | index | index ... | count
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SlotIndexStateEntry {
    slot_index: SlotIndexState,
}

impl TryFrom<&Entry> for SlotIndexStateEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == 0x3269,
            "invalid slot index entry: incorrect header type"
        );
        ensure!(
            entry.header.length == 24,
            "invalid slot index entry: incorrect header length"
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid slot index entry: incorrect header reserved bytes"
        );
        ensure!(
            entry.value.len() == 24,
            "invalid slot index entry: incorrect value length"
        );
        Ok(Self {
            slot_index: SlotIndexState::try_from(entry.clone())?,
        })
    }
}

impl TryInto<Entry> for SlotIndexStateEntry {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Entry, Self::Error> {
        let mut buf: Vec<u64> = vec![];
        buf.push(self.slot_index.starting_slot);
        buf.extend_from_slice(&self.slot_index.indices);
        buf.push(self.slot_index.count);
        let encoded = buf
            .iter()
            .flat_map(|i| i.to_le_bytes().to_vec())
            .collect::<Vec<u8>>();
        Ok(Entry::new(0x3269, encoded))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SlotIndexState {
    starting_slot: u64,
    indices: [u64; 1],
    count: u64,
}

impl TryFrom<Entry> for SlotIndexState {
    type Error = anyhow::Error;

    fn try_from(entry: Entry) -> Result<Self, Self::Error> {
        let starting_slot = u64::from_le_bytes(entry.value[0..8].try_into()?);
        let index = u64::from_le_bytes(entry.value[8..16].try_into()?);
        let indices = [index; 1];

        let count = u64::from_le_bytes(entry.value[(8 + 8)..(8 + 16)].try_into()?);
        Ok(Self {
            starting_slot,
            indices,
            count,
        })
    }
}
