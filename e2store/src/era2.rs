use alloy_primitives::{B256, U256};
use alloy_rlp::{Decodable, RlpDecodable, RlpEncodable};
use anyhow::ensure;
use ethportal_api::types::{
    execution::{block_body::BlockBody, header::Header, receipts::Receipts},
    state_trie::account_state::AccountState,
};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use crate::{
    e2store::{
        stream::E2StoreStream,
        types::{Entry, Header as E2storeHeader, VersionEntry},
    },
    era1::HeaderEntry,
};

// <network-name>-<block-number>-<short-state-root>.era2
//
// era2 := Version | CompressedHeader | account*
// account :=  CompressedAddressHash | CompressedAddressHash | CompressedBytecode | CompressedStorage
// -----
// Version                = { type: 0x3265, data: nil }
// CompressedHeader       = { type: 0x03,   data: snappyFramed(rlp(header)) }
// CompressedAddressHash  = { type: 0x04,   data: snappyFramed(address_hash) }
// CompressedAccountState = { type: 0x05,   data: snappyFramed(rlp(nonce, balance, storage_root, code_hash)) }
// CompressedBytecode     = { type: 0x06,   data: snappyFramed(raw_bytecode) }
// CompressedStorage      = { type: 0x07,   data: snappyFramed(rlp(Vec<StorageItem { storage_index_hash, value }>)) }

/// Represents an era2 `Era2` state snapshot.
/// Unlike era1, not all fields will be stored in the struct, account's will be streamed from an iterator as needed.
pub struct Era2 {
    pub version: VersionEntry,
    pub header: HeaderEntry,

    /// e2store_stream, manages the interactions between the era2 state snapshot
    e2store_stream: E2StoreStream,
}

impl Era2 {
    pub fn initiate_era2_reader(era2_path: &PathBuf) -> anyhow::Result<Self> {
        let mut e2store_stream = E2StoreStream::new(era2_path)?;

        let version = VersionEntry::try_from(&e2store_stream.next_entry()?)?;
        let header = HeaderEntry::try_from(&e2store_stream.next_entry()?)?;

        Ok(Self {
            version,
            header,
            e2store_stream,
        })
    }

    pub fn initiate_empty_era2(era2_path: &PathBuf, header: Header) -> anyhow::Result<Self> {
        let mut e2store_stream = E2StoreStream::new(era2_path)?;

        let version: VersionEntry = (&Entry {
            header: E2storeHeader {
                type_: 0x3265,
                length: 0,
                reserved: 0,
            },
            value: vec![],
        })
            .try_into()?;
        e2store_stream.append_entry(&version.clone().try_into()?)?;

        let header = HeaderEntry { header };
        e2store_stream.append_entry(&header.clone().try_into()?)?;

        Ok(Self {
            version,
            header,
            e2store_stream,
        })
    }

    pub fn next_account(&mut self) -> anyhow::Result<AccountTuple> {
        let account = AccountTuple::try_from(&[
            self.e2store_stream.next_entry()?,
            self.e2store_stream.next_entry()?,
            self.e2store_stream.next_entry()?,
            self.e2store_stream.next_entry()?,
        ])?;
        Ok(account)
    }

    pub fn append_account(&mut self, account: &AccountTuple) -> anyhow::Result<()> {
        let entries: [Entry; 4] = account.clone().try_into()?;
        for entry in entries.iter() {
            self.e2store_stream.append_entry(entry)?;
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct AccountTuple {
    pub address_hash: AddressHashEntry,
    pub account_state: AccountStateEntry,
    pub bytecode: BytecodeEntry,
    pub storage: StorageEntry,
}

impl TryFrom<&[Entry; 4]> for AccountTuple {
    type Error = anyhow::Error;

    fn try_from(entries: &[Entry; 4]) -> anyhow::Result<Self> {
        let address_hash = AddressHashEntry::try_from(&entries[0])?;
        let account_state = AccountStateEntry::try_from(&entries[1])?;
        let bytecode = BytecodeEntry::try_from(&entries[2])?;
        let storage = StorageEntry::try_from(&entries[3])?;
        Ok(Self {
            address_hash,
            account_state,
            bytecode,
            storage,
        })
    }
}

impl TryInto<[Entry; 4]> for AccountTuple {
    type Error = anyhow::Error;

    fn try_into(self) -> anyhow::Result<[Entry; 4]> {
        Ok([
            self.address_hash.try_into()?,
            self.account_state.try_into()?,
            self.bytecode.try_into()?,
            self.storage.try_into()?,
        ])
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct AddressHashEntry {
    pub address_hash: B256,
}

impl TryFrom<&Entry> for AddressHashEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == 0x04,
            "invalid address hash entry: incorrect address hash type"
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid address hash entry: incorrect address hash reserved bytes"
        );
        let mut decoder = snap::read::FrameDecoder::new(&entry.value[..]);
        let mut buf: Vec<u8> = vec![];
        decoder.read_to_end(&mut buf)?;
        let address_hash = B256::from_slice(buf.as_slice());
        Ok(Self { address_hash })
    }
}

impl TryInto<Entry> for AddressHashEntry {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Entry, Self::Error> {
        let buf: Vec<u8> = vec![];
        let mut encoder = snap::write::FrameEncoder::new(buf);
        let _ = encoder.write(self.address_hash.as_slice())?;
        let encoded = encoder.into_inner()?;
        Ok(Entry::new(0x04, encoded))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct AccountStateEntry {
    pub account_state: AccountState,
}

impl TryFrom<&Entry> for AccountStateEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == 0x05,
            "invalid account state entry: incorrect account state type"
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid account state entry: incorrect account state reserved bytes"
        );
        let mut decoder = snap::read::FrameDecoder::new(&entry.value[..]);
        let mut buf: Vec<u8> = vec![];
        decoder.read_to_end(&mut buf)?;
        let account_state = Decodable::decode(&mut buf.as_slice())?;
        Ok(Self { account_state })
    }
}

impl TryInto<Entry> for AccountStateEntry {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Entry, Self::Error> {
        let rlp_encoded = alloy_rlp::encode(self.account_state);
        let buf: Vec<u8> = vec![];
        let mut encoder = snap::write::FrameEncoder::new(buf);
        let _ = encoder.write(&rlp_encoded)?;
        let encoded = encoder.into_inner()?;
        Ok(Entry::new(0x05, encoded))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BytecodeEntry {
    pub bytecode: Vec<u8>,
}

impl TryFrom<&Entry> for BytecodeEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == 0x06,
            "invalid bytecode entry: incorrect bytecode type"
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid bytecode entry: incorrect bytecode reserved bytes"
        );
        let mut decoder = snap::read::FrameDecoder::new(&entry.value[..]);
        let mut bytecode: Vec<u8> = vec![];
        decoder.read_to_end(&mut bytecode)?;
        Ok(Self { bytecode })
    }
}

impl TryInto<Entry> for BytecodeEntry {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Entry, Self::Error> {
        let buf: Vec<u8> = vec![];
        let mut encoder = snap::write::FrameEncoder::new(buf);
        let _ = encoder.write(&self.bytecode)?;
        let encoded = encoder.into_inner()?;
        Ok(Entry::new(0x06, encoded))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct StorageEntry {
    pub storage: Vec<StorageItem>,
}

#[derive(Clone, Eq, PartialEq, Debug, RlpEncodable, RlpDecodable)]
pub struct StorageItem {
    pub storage_index_hash: B256,
    pub value: B256,
}

impl TryFrom<&Entry> for StorageEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == 0x07,
            "invalid storage entry: incorrect storage type"
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid storage entry: incorrect storage reserved bytes"
        );
        let mut decoder = snap::read::FrameDecoder::new(&entry.value[..]);
        let mut buf: Vec<u8> = vec![];
        decoder.read_to_end(&mut buf)?;
        let storage = Decodable::decode(&mut buf.as_slice())?;
        Ok(Self { storage })
    }
}

impl TryInto<Entry> for StorageEntry {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Entry, Self::Error> {
        let rlp_encoded = alloy_rlp::encode(self.storage);
        let buf: Vec<u8> = vec![];
        let mut encoder = snap::write::FrameEncoder::new(buf);
        let _ = encoder.write(&rlp_encoded)?;
        let encoded = encoder.into_inner()?;
        Ok(Entry::new(0x07, encoded))
    }
}
