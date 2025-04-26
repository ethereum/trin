use std::{
    fs,
    io::{Read, Write},
};

use anyhow::{anyhow, ensure};
use ethportal_api::consensus::{
    beacon_block::SignedBeaconBlock, beacon_state::BeaconState,
    constants::SLOTS_PER_HISTORICAL_ROOT, fork::ForkName,
};
use ssz::Encode;

use crate::{
    e2store::{
        memory::E2StoreMemory,
        types::{Entry, Header, VersionEntry},
    },
    entry_types,
};

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
        let file_length = buf.len();
        let file = E2StoreMemory::deserialize(buf)?;
        let version = VersionEntry::try_from(&file.entries[0])?;
        let entries_length = file.entries.len();
        let mut blocks = vec![];

        let slot_index_block = SlotIndexBlockEntry::try_from(&file.entries[entries_length - 2])?;
        let slot_index_state = SlotIndexStateEntry::try_from(&file.entries[entries_length - 1])?;
        let slot_indexes = Era::get_block_slot_indexes(file_length, &slot_index_block);

        // an era file has 4 entries which are not blocks
        ensure!(
            slot_indexes.len() == entries_length - 4,
            "invalid slot index block: incorrect count {} {}",
            slot_indexes.len(),
            entries_length - 4
        );
        for (index, slot) in slot_indexes.into_iter().enumerate() {
            let entry = &file.entries[index + 1];
            let fork = get_beacon_fork(slot);
            let beacon_block = CompressedSignedBeaconBlock::try_from(entry, fork)?;
            blocks.push(beacon_block);
        }
        let fork = get_beacon_fork(slot_index_state.slot_index.starting_slot);
        let era_state = CompressedBeaconState::try_from(&file.entries[entries_length - 3], fork)?;

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
        let file = E2StoreMemory::deserialize(buf)?;
        // The compressed `BeaconState` is the second to last entry in the file.
        let entries_length = file.entries.len();
        let slot_index_state = SlotIndexStateEntry::try_from(&file.entries[entries_length - 1])?;
        let fork = get_beacon_fork(slot_index_state.slot_index.starting_slot);
        let era_state = CompressedBeaconState::try_from(&file.entries[entries_length - 3], fork)?;
        Ok(era_state.state)
    }

    fn get_block_slot_indexes(
        file_length: usize,
        slot_index_block_entry: &SlotIndexBlockEntry,
    ) -> Vec<u64> {
        let beginning_of_index_record = file_length
            - SlotIndexBlockEntry::SERIALIZED_SIZE
            - SlotIndexStateEntry::SERIALIZED_SIZE;
        let beginning_of_file_offset = -(beginning_of_index_record as i64);

        slot_index_block_entry
            .slot_index
            .indices
            .iter()
            .enumerate()
            .filter_map(|(i, offset)| {
                if *offset != beginning_of_file_offset {
                    Some(slot_index_block_entry.slot_index.starting_slot + i as u64)
                } else {
                    None
                }
            })
            .collect::<Vec<u64>>()
    }

    pub fn write(&self) -> anyhow::Result<Vec<u8>> {
        let mut entries: Vec<Entry> = vec![];
        let version_entry = Entry::from(&self.version);
        entries.push(version_entry);
        for block in &self.blocks {
            let block_entry = Entry::try_from(block)?;
            entries.push(block_entry);
        }
        let era_state_entry = Entry::try_from(&self.era_state)?;
        entries.push(era_state_entry);
        let slot_index_block_entry = Entry::from(&self.slot_index_block);
        entries.push(slot_index_block_entry);
        let slot_index_state_entry = Entry::from(&self.slot_index_state);
        entries.push(slot_index_state_entry);
        let file = E2StoreMemory { entries };

        let file_length = file.length();
        let mut buf = vec![0; file_length];
        file.write(&mut buf)?;
        Ok(buf)
    }

    pub fn contains(&self, block_number: u64) -> bool {
        if self.blocks.is_empty() {
            return false;
        }
        let first_block_number = self.blocks[0].block.execution_block_number();
        let last_block_number = self.blocks[self.blocks.len() - 1]
            .block
            .execution_block_number();
        (first_block_number..=last_block_number).contains(&block_number)
    }

    pub fn epoch_index(&self) -> u64 {
        self.slot_index_state.slot_index.starting_slot / SLOTS_PER_HISTORICAL_ROOT as u64
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct CompressedSignedBeaconBlock {
    pub block: SignedBeaconBlock,
}

impl CompressedSignedBeaconBlock {
    pub fn try_from(entry: &Entry, fork: ForkName) -> Result<Self, anyhow::Error> {
        ensure!(
            entry.header.type_ == entry_types::COMPRESSED_SIGNED_BEACON_BLOCK,
            "invalid compressed signed beacon block entry: incorrect header type"
        );

        let mut decoder = snap::read::FrameDecoder::new(&entry.value[..]);
        let mut buf: Vec<u8> = vec![];
        decoder.read_to_end(&mut buf)?;

        let block = SignedBeaconBlock::from_ssz_bytes(&buf, fork)
            .map_err(|_| anyhow!("Unable to ssz decode beacon block body"))?;
        Ok(Self { block })
    }
}

impl TryFrom<&CompressedSignedBeaconBlock> for Entry {
    type Error = anyhow::Error;

    fn try_from(value: &CompressedSignedBeaconBlock) -> Result<Self, Self::Error> {
        let ssz_encoded = value.block.as_ssz_bytes();
        let buf: Vec<u8> = vec![];
        let mut snappy_encoder = snap::write::FrameEncoder::new(buf);
        let _ = snappy_encoder.write(&ssz_encoded)?;
        let snappy_encoded = snappy_encoder.into_inner()?;

        Ok(Entry::new(
            entry_types::COMPRESSED_SIGNED_BEACON_BLOCK,
            snappy_encoded,
        ))
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct CompressedBeaconState {
    pub state: BeaconState,
}

impl CompressedBeaconState {
    fn try_from(entry: &Entry, fork: ForkName) -> Result<Self, anyhow::Error> {
        ensure!(
            entry.header.type_ == entry_types::COMPRESSED_BEACON_STATE,
            "invalid compressed beacon state entry: incorrect header type"
        );

        let mut decoder = snap::read::FrameDecoder::new(&entry.value[..]);
        let mut buf: Vec<u8> = vec![];
        decoder.read_to_end(&mut buf)?;

        let state = BeaconState::from_ssz_bytes(&buf, fork)
            .map_err(|_| anyhow!("Unable to decode beacon state from ssz bytes"))?;
        Ok(Self { state })
    }
}

impl TryFrom<&CompressedBeaconState> for Entry {
    type Error = anyhow::Error;

    fn try_from(value: &CompressedBeaconState) -> Result<Self, Self::Error> {
        let ssz_encoded = value.state.as_ssz_bytes();
        let buf: Vec<u8> = vec![];
        let mut snappy_encoder = snap::write::FrameEncoder::new(buf);
        let _ = snappy_encoder.write(&ssz_encoded)?;
        let snappy_encoded = snappy_encoder.into_inner()?;

        Ok(Entry::new(
            entry_types::COMPRESSED_BEACON_STATE,
            snappy_encoded,
        ))
    }
}

// slot-index := starting-slot | index | index | index ... | count
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SlotIndexBlockEntry {
    pub slot_index: SlotIndexBlock,
}

impl SlotIndexBlockEntry {
    pub const SERIALIZED_SIZE: usize =
        Header::SERIALIZED_SIZE as usize + SlotIndexBlock::SERIALIZED_SIZE;
}

impl TryFrom<&Entry> for SlotIndexBlockEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == entry_types::SLOT_INDEX,
            "invalid slot index block entry: incorrect header type"
        );
        ensure!(
            entry.header.length == SlotIndexBlock::SERIALIZED_SIZE as u32,
            "invalid slot index entry: incorrect header length"
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid slot index entry: incorrect header reserved bytes"
        );
        ensure!(
            entry.value.len() == SlotIndexBlock::SERIALIZED_SIZE,
            "invalid slot index entry: incorrect value length"
        );
        Ok(Self {
            slot_index: SlotIndexBlock::try_from(entry.clone())?,
        })
    }
}

impl From<&SlotIndexBlockEntry> for Entry {
    fn from(value: &SlotIndexBlockEntry) -> Self {
        let mut buf = vec![];

        buf.extend_from_slice(&value.slot_index.starting_slot.to_le_bytes());
        for index in &value.slot_index.indices {
            buf.extend_from_slice(&index.to_le_bytes());
        }
        buf.extend_from_slice(&value.slot_index.count.to_le_bytes());

        Entry::new(entry_types::SLOT_INDEX, buf)
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SlotIndexBlock {
    pub starting_slot: u64,
    pub indices: [i64; SLOTS_PER_HISTORICAL_ROOT],
    pub count: u64,
}

impl SlotIndexBlock {
    pub const SERIALIZED_SIZE: usize = 8 * (1 + SLOTS_PER_HISTORICAL_ROOT + 1);
}

impl TryFrom<Entry> for SlotIndexBlock {
    type Error = anyhow::Error;

    fn try_from(entry: Entry) -> Result<Self, Self::Error> {
        let starting_slot = u64::from_le_bytes(entry.value[0..8].try_into()?);
        let mut indices = [0i64; SLOTS_PER_HISTORICAL_ROOT];
        for (i, index) in indices.iter_mut().enumerate() {
            *index = i64::from_le_bytes(entry.value[(i * 8 + 8)..(i * 8 + 16)].try_into()?);
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
    pub slot_index: SlotIndexState,
}

impl SlotIndexStateEntry {
    pub const SERIALIZED_SIZE: usize =
        Header::SERIALIZED_SIZE as usize + SlotIndexState::SERIALIZED_SIZE;
}

impl TryFrom<&Entry> for SlotIndexStateEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == entry_types::SLOT_INDEX,
            "invalid slot index state entry: incorrect header type"
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

impl From<&SlotIndexStateEntry> for Entry {
    fn from(value: &SlotIndexStateEntry) -> Self {
        let mut buf = vec![];

        buf.extend_from_slice(&value.slot_index.starting_slot.to_le_bytes());
        for index in &value.slot_index.indices {
            buf.extend_from_slice(&index.to_le_bytes());
        }
        buf.extend_from_slice(&value.slot_index.count.to_le_bytes());

        Entry::new(entry_types::SLOT_INDEX, buf)
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SlotIndexState {
    pub starting_slot: u64,
    indices: [i64; 1],
    count: u64,
}

impl SlotIndexState {
    pub const SERIALIZED_SIZE: usize = 8 * (1 + 1 + 1);
}

impl TryFrom<Entry> for SlotIndexState {
    type Error = anyhow::Error;

    fn try_from(entry: Entry) -> Result<Self, Self::Error> {
        let starting_slot = u64::from_le_bytes(entry.value[0..8].try_into()?);
        let index = i64::from_le_bytes(entry.value[8..16].try_into()?);
        let indices = [index; 1];

        let count = u64::from_le_bytes(entry.value[(8 + 8)..(8 + 16)].try_into()?);
        Ok(Self {
            starting_slot,
            indices,
            count,
        })
    }
}

pub fn get_beacon_fork(slot_index: u64) -> ForkName {
    if slot_index < 4_636_672 {
        panic!("e2store/era doesn't support this fork");
    } else if (4_636_672..6_209_536).contains(&slot_index) {
        ForkName::Bellatrix
    } else if (6_209_536..8_626_176).contains(&slot_index) {
        ForkName::Capella
    } else {
        ForkName::Deneb
    }
}
