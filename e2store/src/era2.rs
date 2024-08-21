use std::{
    io::{ErrorKind, Read, Write},
    ops::Deref,
    path::{Path, PathBuf},
};

use alloy_primitives::{hex, B256, U256};
use alloy_rlp::{Decodable, RlpDecodable, RlpEncodable};
use anyhow::{bail, ensure};
use ethportal_api::types::{execution::header::Header, state_trie::account_state::AccountState};

use crate::{
    e2store::{
        stream::E2StoreStream,
        types::{Entry, VersionEntry},
    },
    types::HeaderEntry,
    utils::underlying_io_error_kind,
};

// <network-name>-<block-number>-<short-state-root>.era2
//
// era2 := Version | CompressedHeader | account*
// account :=  CompressedAccount | CompressedStorage*
// -----
// Version                     = { type: 0x3265, data: nil }
// CompressedHeader            = { type: 0x03,   data: snappyFramed(rlp(header)) }
// CompressedAccount           = { type: 0x08,   data: snappyFramed(rlp(address_hash, rlp(nonce,
// balance, storage_root, code_hash), raw_bytecode, storage_entry_count)) }
// CompressedStorage           = { type: 0x09,   data: snappyFramed(rlp(Vec<StorageItem {
// storage_index_hash, value }>)) }
// -----
// CompressedStorage can have a max of 10 million storage items, records must be filled before
// creating a new one, and must be sorted by storage_index_hash across all entries.

/// Represents an era2 `Era2` state snapshot.
/// Unlike era1, not all fields will be stored in the struct, account's will be streamed from an
/// iterator as needed.
pub struct Era2 {
    pub version: VersionEntry,
    pub header: HeaderEntry,

    /// e2store_stream, manages the interactions between the era2 state snapshot
    e2store_stream: E2StoreStream,
    pending_storage_entries: u32,
    path: PathBuf,
}

impl Era2 {
    pub fn open(path: PathBuf) -> anyhow::Result<Self> {
        let mut e2store_stream = E2StoreStream::open(&path)?;

        let version = VersionEntry::try_from(&e2store_stream.next_entry()?)?;
        let header = HeaderEntry::try_from(&e2store_stream.next_entry()?)?;

        Ok(Self {
            version,
            header,
            e2store_stream,
            pending_storage_entries: 0,
            path,
        })
    }

    pub fn create(path: PathBuf, header: Header) -> anyhow::Result<Self> {
        ensure!(path.is_dir(), "era2 path is not a directory: {:?}", path);
        let path = path.join(format!(
            "mainnet-{:010}-{}.era2",
            header.number,
            hex::encode(&header.state_root.as_slice()[..4])
        ));
        ensure!(!path.exists(), "era2 file already exists: {:?}", path);
        let mut e2store_stream = E2StoreStream::create(&path)?;

        let version = VersionEntry::default();
        e2store_stream.append_entry(&version.clone().into())?;

        let header = HeaderEntry { header };
        e2store_stream.append_entry(&header.clone().try_into()?)?;

        Ok(Self {
            version,
            header,
            e2store_stream,
            pending_storage_entries: 0,
            path,
        })
    }

    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    pub fn append_entry(&mut self, entry: &AccountOrStorageEntry) -> anyhow::Result<usize> {
        let size = match entry {
            AccountOrStorageEntry::Account(account) => {
                ensure!(
                    self.pending_storage_entries == 0,
                    "Invalid append entry state: expected a storage entry, got an account entry. Still have {} storage entries left to append", self.pending_storage_entries                
                );

                self.pending_storage_entries = account.storage_count;
                let entry: Entry = account.clone().try_into()?;
                self.e2store_stream.append_entry(&entry)?;
                entry.value.len()
            }
            AccountOrStorageEntry::Storage(storage) => {
                match self.pending_storage_entries {
                    0 => bail!("Invalid append entry state: expected an account entry, got a storage entry. No storage entries left to append for the account"),
                    1 => ensure!(
                        storage.len() <= 10_000_000,
                        "Storage entry can't have more than 10 million items",
                    ),
                    _ => ensure!(
                        storage.len() == 10_000_000,
                        "Only last storage entry can have less than 10 million items",
                    ),
                }

                self.pending_storage_entries -= 1;
                let entry: Entry = storage.clone().try_into()?;
                self.e2store_stream.append_entry(&entry)?;
                entry.value.len()
            }
        };
        Ok(size)
    }
}

impl Iterator for Era2 {
    type Item = AccountOrStorageEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pending_storage_entries > 0 {
            self.pending_storage_entries -= 1;

            let raw_storage_entry = match self.e2store_stream.next_entry() {
                Ok(raw_storage_entry) => raw_storage_entry,
                Err(err) => panic!("Failed to read next storage entry: {:?}", err),
            };

            let storage_entry = match StorageEntry::try_from(&raw_storage_entry) {
                Ok(storage_entry) => storage_entry,
                Err(err) => panic!("Failed to decode next storage entry: {:?}", err),
            };
            return Some(AccountOrStorageEntry::Storage(storage_entry));
        }

        let raw_account_entry = match self.e2store_stream.next_entry() {
            Ok(raw_account_entry) => raw_account_entry,
            Err(err) => match err {
                // If we read to the end of the error file we should get this
                err if underlying_io_error_kind(&err).is_some()
                    && underlying_io_error_kind(&err)
                        .expect("We already checked there is some")
                        == ErrorKind::UnexpectedEof =>
                {
                    return None
                }
                err => panic!("Failed reading next account entry: {:?}", err),
            },
        };

        let account_entry = match AccountEntry::try_from(&raw_account_entry) {
            Ok(account_entry) => account_entry,
            Err(err) => panic!("Failed decoding next account entry: {:?}", err),
        };
        self.pending_storage_entries = account_entry.storage_count;
        Some(AccountOrStorageEntry::Account(account_entry))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum AccountOrStorageEntry {
    Account(AccountEntry),
    Storage(StorageEntry),
}

#[derive(Clone, Eq, PartialEq, Debug, RlpEncodable, RlpDecodable)]
pub struct AccountEntry {
    pub address_hash: B256,
    pub account_state: AccountState,
    pub bytecode: Vec<u8>,
    pub storage_count: u32,
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

impl TryFrom<AccountEntry> for Entry {
    type Error = anyhow::Error;

    fn try_from(value: AccountEntry) -> Result<Self, Self::Error> {
        let rlp_encoded = alloy_rlp::encode(value);
        let mut encoder = snap::write::FrameEncoder::new(vec![]);
        let bytes_written = encoder.write(&rlp_encoded)?;
        ensure!(
            bytes_written == rlp_encoded.len(),
            "FrameEncoder should write whole rlp encoding"
        );
        let encoded = encoder.into_inner()?;
        Ok(Entry::new(0x08, encoded))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct StorageEntry(Vec<StorageItem>);

impl Deref for StorageEntry {
    type Target = Vec<StorageItem>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
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
        Ok(Self(storage))
    }
}

impl TryFrom<StorageEntry> for Entry {
    type Error = anyhow::Error;

    fn try_from(value: StorageEntry) -> Result<Self, Self::Error> {
        let rlp_encoded = alloy_rlp::encode(value.0);
        let mut encoder = snap::write::FrameEncoder::new(vec![]);
        let bytes_written = encoder.write(&rlp_encoded)?;
        ensure!(
            bytes_written == rlp_encoded.len(),
            "FrameEncoder should write whole rlp encoding"
        );
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
    fn test_era2_stream_write_and_read() -> anyhow::Result<()> {
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

        let tmp_path = tmp_path.join(format!(
            "mainnet-{:010}-{}.era2",
            header.number,
            hex::encode(&header.state_root.as_slice()[..4])
        ));
        assert_eq!(era2_write_file.path(), tmp_path.as_path());

        let account = AccountOrStorageEntry::Account(AccountEntry {
            address_hash: B256::default(),
            account_state: AccountState::default(),
            bytecode: vec![],
            storage_count: 1,
        });

        assert_eq!(era2_write_file.pending_storage_entries, 0);
        let size = era2_write_file.append_entry(&account)?;
        assert_eq!(size, 101);
        assert_eq!(era2_write_file.pending_storage_entries, 1);

        let storage = AccountOrStorageEntry::Storage(StorageEntry(vec![StorageItem {
            storage_index_hash: B256::default(),
            value: U256::default(),
        }]));

        let size = era2_write_file.append_entry(&storage)?;
        assert_eq!(size, 29);
        assert_eq!(era2_write_file.pending_storage_entries, 0);

        // read results and see if they match
        let mut era2_read_file = Era2::open(tmp_path.clone())?;
        assert_eq!(era2_read_file.path(), tmp_path.as_path());

        let default_version_entry = VersionEntry::default();
        assert_eq!(era2_read_file.version, default_version_entry);
        assert_eq!(era2_read_file.header, HeaderEntry { header });
        assert_eq!(era2_read_file.pending_storage_entries, 0);
        let read_account_tuple = era2_read_file.next().unwrap();
        assert_eq!(account, read_account_tuple);
        assert_eq!(era2_read_file.pending_storage_entries, 1);

        let read_storage_tuple = era2_read_file.next().unwrap();
        assert_eq!(storage, read_storage_tuple);
        assert_eq!(era2_read_file.pending_storage_entries, 0);

        // cleanup
        tmp_dir.close()?;
        Ok(())
    }
}
