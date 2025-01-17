use std::path::PathBuf;

use alloy::primitives::{keccak256, B256};
use anyhow::bail;
use clap::Parser;
use tracing::info;
use trin_e2store::era2::{self, AccountOrStorageEntry, Era2Reader};

#[derive(Debug, Parser)]
#[command(
    name = "Era2 stats",
    about = "Reads the era2 file, validates the format, and prints stats about it."
)]
struct Config {
    #[arg(help = "The path to the era2 file.")]
    path: PathBuf,
}

#[derive(Debug, Default)]
struct Stats {
    account_count: usize,
    bytecode_count: usize,
    storage_entry_count: usize,
    storage_item_count: usize,
}

/// Reads the era2 file, validates the format, and prints stats about it.
///
/// It can be run with following command:
///
/// ```bash
/// cargo run --release -p e2store --bin era2-stats --features era2-stats-binary -- <path>
/// ```
fn main() -> anyhow::Result<()> {
    trin_utils::log::init_tracing_logger();

    let config = Config::parse();
    let mut reader = Era2Reader::open(&config.path)?;

    info!(
        "Processing era2 file for block: {}",
        reader.header.header.number
    );

    let mut last_address_hash = B256::ZERO;

    let mut stats = Stats::default();
    while let Some(entry) = reader.next() {
        let AccountOrStorageEntry::Account(account) = entry else {
            bail!("Expected account entry");
        };
        stats.account_count += 1;

        assert!(
            account.address_hash > last_address_hash,
            "Expected increasing order of accounts: {last_address_hash} is before {}",
            account.address_hash
        );
        last_address_hash = account.address_hash;

        assert_eq!(
            keccak256(&account.bytecode),
            account.account_state.code_hash,
            "Invalid code hash",
        );

        if !account.bytecode.is_empty() {
            stats.bytecode_count += 1;
        }

        let mut last_storage_item = B256::ZERO;
        for index in 0..account.storage_count {
            let Some(AccountOrStorageEntry::Storage(storage)) = reader.next() else {
                bail!(
                    "Expected storage entry for account: {}",
                    account.address_hash
                );
            };
            stats.storage_entry_count += 1;
            stats.storage_item_count += storage.len();

            // Check that every storage entry is full (has 10M items), except the last one.
            if index + 1 < account.storage_count {
                assert_eq!(
                    storage.len(),
                    era2::MAX_STORAGE_ITEMS,
                    "Non-final storage entry (address_hash: {}, index: {index}/{}) should be full, but has {} items instead",
                    account.address_hash,
                    account.storage_count,
                    storage.len(),
                );
            }

            for item in storage.iter() {
                assert!(
                    item.storage_index_hash > last_storage_item,
                    "Expected increasing order of storage items (address hash: {}): {last_storage_item} is before {}",
                    account.address_hash,
                    item.storage_index_hash,
                );
                last_storage_item = item.storage_index_hash;
            }
        }

        if stats.account_count % 1_000_000 == 0 {
            info!("Processed {} accounts", stats.account_count);
        }
    }

    info!("Done! {stats:#?}");
    Ok(())
}
