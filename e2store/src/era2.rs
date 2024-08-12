use std::{
    io::{Read, Write},
    path::PathBuf,
};

use alloy_primitives::{hex, B256, U256};
use alloy_rlp::{Decodable, RlpDecodable, RlpEncodable};
use anyhow::ensure;
use core::panic;
use ethportal_api::types::{execution::header::Header, state_trie::account_state::AccountState};

use crate::{
    e2store::{
        stream::E2StoreStream,
        types::{Entry, VersionEntry},
    },
    era1::HeaderEntry,
};

// <network-name>-<block-number>-<short-state-root>.era2
//
// era2 := Version | CompressedHeader | account*
// account :=  CompressedAccount | CompressedStorage*
// -----
// Version                     = { type: 0x3265, data: nil }
// CompressedHeader            = { type: 0x03,   data: snappyFramed(rlp(header)) }
// CompressedAccount           = { type: 0x08,   data: snappyFramed(rlp(address_hash, rlp(nonce,
// balance, storage_root, code_hash), raw_bytecode, storage_entry_count) }
// CompressedStorage           = { type: 0x09,   data: snappyFramed(rlp(Vec<StorageItem {
// storage_index_hash, value }>)) }
// -----
// CompressedStorage can have a max of 10k storage items, records must be filled before
// creating a new one

/// Represents an era2 `Era2` state snapshot.
/// Unlike era1, not all fields will be stored in the struct, account's will be streamed from an
/// iterator as needed.
pub struct Era2 {
    pub version: VersionEntry,
    pub header: HeaderEntry,

    /// e2store_stream, manages the interactions between the era2 state snapshot
    e2store_stream: E2StoreStream,
    storage_entries_left_to_decode: u16,
}

impl Era2 {
    pub fn open(era2_path: &PathBuf) -> anyhow::Result<Self> {
        let mut e2store_stream = E2StoreStream::open(era2_path)?;

        let version = VersionEntry::try_from(&e2store_stream.next_entry()?)?;
        let header = HeaderEntry::try_from(&e2store_stream.next_entry()?)?;

        Ok(Self {
            version,
            header,
            e2store_stream,
            storage_entries_left_to_decode: 0,
        })
    }

    pub fn create(era2_path: PathBuf, header: Header) -> anyhow::Result<Self> {
        if era2_path.is_file() {
            panic!(
                "era2_path is not a directory, it is a file: {:?}",
                era2_path
            );
        }
        let era2_path = era2_path.join(format!(
            "mainnet-{:010}-{}.era2",
            header.number,
            hex::encode(&header.state_root.as_slice()[..4])
        ));
        if era2_path.exists() {
            panic!("era2 file already exists: {:?}", era2_path);
        }
        let mut e2store_stream = E2StoreStream::create(&era2_path)?;

        let version = VersionEntry::default();
        e2store_stream.append_entry(&version.clone().into())?;

        let header = HeaderEntry { header };
        e2store_stream.append_entry(&header.clone().try_into()?)?;

        Ok(Self {
            version,
            header,
            e2store_stream,
            storage_entries_left_to_decode: 0,
        })
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> anyhow::Result<Era2StreamEntry> {
        if self.storage_entries_left_to_decode > 0 {
            self.storage_entries_left_to_decode -= 1;
            return Ok(Era2StreamEntry::Storage(StorageEntry::try_from(
                &self.e2store_stream.next_entry()?,
            )?));
        }
        let account = AccountEntry::try_from(&self.e2store_stream.next_entry()?)?;
        self.storage_entries_left_to_decode = account.storage_count;
        Ok(Era2StreamEntry::Account(account))
    }

    pub fn append_entry(&mut self, entry: &Era2StreamEntry) -> anyhow::Result<usize> {
        let size = match entry {
            Era2StreamEntry::Account(account) => {
                if self.storage_entries_left_to_decode != 0 {
                    panic!("Invalid append entry state: expected a storage entry, got an account entry. Still have {} storage entries left to append", self.storage_entries_left_to_decode);
                }

                self.storage_entries_left_to_decode = account.storage_count;
                let entry: Entry = account.clone().try_into()?;
                self.e2store_stream.append_entry(&entry)?;
                entry.value.len()
            }
            Era2StreamEntry::Storage(storage) => {
                if self.storage_entries_left_to_decode == 0 {
                    panic!("Invalid append entry state: expected an account entry, got a storage entry. No storage entries left to append for the account");
                }

                self.storage_entries_left_to_decode -= 1;
                let entry: Entry = storage.clone().try_into()?;
                self.e2store_stream.append_entry(&entry)?;
                entry.value.len()
            }
        };
        Ok(size)
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Era2StreamEntry {
    Account(AccountEntry),
    Storage(StorageEntry),
}

#[derive(Clone, Eq, PartialEq, Debug, RlpEncodable, RlpDecodable)]
pub struct AccountEntry {
    pub address_hash: B256,
    pub account_state: AccountState,
    pub bytecode: Vec<u8>,
    pub storage_count: u16,
}

impl TryFrom<&Entry> for AccountEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == 0x08,
            "invalid account entry: incorrect account type"
        );
        ensure!(
            entry.header.reserved == 0,
            "invalid account entry: incorrect account reserved bytes"
        );
        let mut decoder = snap::read::FrameDecoder::new(&entry.value[..]);
        let mut buf: Vec<u8> = vec![];
        decoder.read_to_end(&mut buf)?;
        let account = Decodable::decode(&mut buf.as_slice())?;
        Ok(account)
    }
}

impl TryInto<Entry> for AccountEntry {
    type Error = anyhow::Error;

    fn try_into(self) -> anyhow::Result<Entry> {
        let rlp_encoded = alloy_rlp::encode(self);
        let buf: Vec<u8> = vec![];
        let mut encoder = snap::write::FrameEncoder::new(buf);
        let _ = encoder.write(&rlp_encoded)?;
        let encoded = encoder.into_inner()?;
        Ok(Entry::new(0x08, encoded))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct StorageEntry {
    pub storage: Vec<StorageItem>,
}

#[derive(Clone, Eq, PartialEq, Debug, RlpEncodable, RlpDecodable)]
pub struct StorageItem {
    pub storage_index_hash: B256,
    pub value: U256,
}

impl TryFrom<&Entry> for StorageEntry {
    type Error = anyhow::Error;

    fn try_from(entry: &Entry) -> Result<Self, Self::Error> {
        ensure!(
            entry.header.type_ == 0x09,
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
        Ok(Entry::new(0x09, encoded))
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, Bloom, B64};
    use tempfile::TempDir;

    use crate::e2store::types::VersionEntry;

    use super::*;

    #[test]
    fn test_e2store_stream_write_and_read() -> anyhow::Result<()> {
        // setup
        let tmp_dir = TempDir::new()?;
        let tmp_path = tmp_dir.as_ref().to_path_buf();

        // create fake execution block header
        let header = Header {
            parent_hash: B256::default(),
            uncles_hash: B256::default(),
            author: Address::random(),
            state_root: B256::default(),
            transactions_root: B256::default(),
            receipts_root: B256::default(),
            logs_bloom: Bloom::default(),
            difficulty: U256::default(),
            number: 5_000_000,
            gas_limit: U256::default(),
            gas_used: U256::default(),
            timestamp: u64::default(),
            extra_data: Vec::default(),
            mix_hash: Some(B256::default()),
            nonce: Some(B64::default()),
            base_fee_per_gas: None,
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
        };

        // create a new e2store file and write some data to it
        let mut era2_write_file = Era2::create(tmp_path.clone(), header.clone())?;

        let account = Era2StreamEntry::Account(AccountEntry {
            address_hash: B256::default(),
            account_state: AccountState::default(),
            bytecode: vec![],
            storage_count: 1,
        });

        assert_eq!(era2_write_file.storage_entries_left_to_decode, 0);
        let size = era2_write_file.append_entry(&account)?;
        assert_eq!(size, 101);
        assert_eq!(era2_write_file.storage_entries_left_to_decode, 1);

        let storage = Era2StreamEntry::Storage(StorageEntry {
            storage: vec![StorageItem {
                storage_index_hash: B256::default(),
                value: U256::default(),
            }],
        });

        let size = era2_write_file.append_entry(&storage)?;
        assert_eq!(size, 29);
        assert_eq!(era2_write_file.storage_entries_left_to_decode, 0);

        // read results and see if they match
        let tmp_path = tmp_path.join(format!(
            "mainnet-{:010}-{}.era2",
            header.number,
            hex::encode(&header.state_root.as_slice()[..4])
        ));
        let mut era2_read_file = Era2::open(&tmp_path)?;

        let default_version_entry = VersionEntry::default();
        assert_eq!(era2_read_file.version, default_version_entry);
        assert_eq!(era2_read_file.header, HeaderEntry { header });
        assert_eq!(era2_read_file.storage_entries_left_to_decode, 0);
        let read_account_tuple = era2_read_file.next()?;
        assert_eq!(account, read_account_tuple);
        assert_eq!(era2_read_file.storage_entries_left_to_decode, 1);

        let read_storage_tuple = era2_read_file.next()?;
        assert_eq!(storage, read_storage_tuple);
        assert_eq!(era2_read_file.storage_entries_left_to_decode, 0);

        // cleanup
        tmp_dir.close()?;
        Ok(())
    }
}
