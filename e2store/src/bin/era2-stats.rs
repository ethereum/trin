use std::path::PathBuf;

use anyhow::bail;
use clap::Parser;
use e2store::era2::{AccountOrStorageEntry, Era2Reader};
use tracing::info;

#[derive(Debug, Parser)]
#[command(
    name = "Era2 stats",
    about = "Reads the era2 file and prints stats about it."
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

/// Reads the era2 file and prints stats about it.
///
/// It can be run with following command:
///
/// ```bash
/// cargo run -p e2store --bin era2-stats --features era2-stats-binary -- <path>
/// ```
fn main() -> anyhow::Result<()> {
    trin_utils::log::init_tracing_logger();

    let config = Config::parse();
    let mut reader = Era2Reader::open(&config.path)?;

    info!(
        "Processing era2 file for block: {}",
        reader.header.header.number
    );

    let mut stats = Stats::default();
    while let Some(entry) = reader.next() {
        let AccountOrStorageEntry::Account(account) = entry else {
            bail!("Expected account entry");
        };
        stats.account_count += 1;

        if !account.bytecode.is_empty() {
            stats.bytecode_count += 1;
        }

        for _ in 0..account.storage_count {
            let Some(AccountOrStorageEntry::Storage(storage)) = reader.next() else {
                bail!(
                    "Expected storage entry for account: {}",
                    account.address_hash
                );
            };
            stats.storage_entry_count += 1;
            stats.storage_item_count += storage.len();
        }

        if stats.account_count % 1_000_000 == 0 {
            info!("Processed {} accounts", stats.account_count);
        }
    }

    info!("Done! {stats:#?}");
    Ok(())
}
