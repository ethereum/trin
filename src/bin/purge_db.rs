use anyhow::Result;
use clap::{Parser, ValueEnum};
use discv5::enr::{CombinedKey, EnrBuilder};
use ethereum_types::H256;
use rocksdb::IteratorMode;
use ssz::Decode;
use tracing::{info, warn};

use ethportal_api::types::execution::accumulator::EpochAccumulator;
use ethportal_api::types::execution::block_body::BlockBody;
use ethportal_api::types::execution::header::HeaderWithProof;
use ethportal_api::types::execution::receipts::Receipts;
use ethportal_api::utils::bytes::hex_encode;
use ethportal_api::HistoryContentKey;
use portalnet::storage::{PortalStorage, PortalStorageConfig};
use portalnet::types::messages::ProtocolId;
use portalnet::utils::db::{configure_node_data_dir, configure_trin_data_dir};
use trin_utils::log::init_tracing_logger;

///
/// This script will iterate through all content id / key pairs in rocksd & meta db.
/// However, if it is run in "invalid-only" mode, it will error if it encounters any
/// non-history network content. Since we only support history network content, this
/// shouldn't be a problem, but as we add support for more sub-networks this script will
/// need to be updated to avoid panicking.
///
pub fn main() -> Result<()> {
    init_tracing_logger();
    let purge_config = PurgeConfig::parse();

    let enr_key =
        CombinedKey::secp256k1_from_bytes(purge_config.private_key.0.clone().as_mut_slice())
            .expect("Failed to create ENR key");
    let enr = EnrBuilder::new("v4").build(&enr_key).unwrap();
    let node_id = enr.node_id();
    let trin_data_dir = configure_trin_data_dir(false)?;
    let (node_data_dir, _) =
        configure_node_data_dir(trin_data_dir, Some(purge_config.private_key))?;
    info!("Purging data for NodeID: {node_id}");
    info!("DB Path: {node_data_dir:?}");

    // Capacity is 0 since it (eg. for data radius calculation) is irrelevant when only removing data.
    let capacity = 0;
    let protocol = ProtocolId::History;
    let config = PortalStorageConfig::new(capacity, node_data_dir, node_id)?;
    let storage =
        PortalStorage::new(config.clone(), protocol).expect("Failed to create portal storage");
    let iter = config.db.iterator(IteratorMode::Start);
    let mut item_count = 0;
    let mut remove_count = 0;
    for (id, value) in iter {
        item_count += 1;
        let mut content_id = [0u8; 32];
        content_id.copy_from_slice(&id);
        match purge_config.mode {
            PurgeMode::All => match storage.evict(content_id) {
                Ok(_) => remove_count += 1,
                Err(err) => {
                    warn!("Error occurred while evicting content id: {content_id:?} - {err:?}")
                }
            },
            PurgeMode::InvalidOnly => {
                // naked unwrap since we shouldn't be storing any invalid content keys
                let key_bytes = match storage.lookup_content_key(content_id) {
                    Ok(Some(k)) => k,
                    Ok(None) => {
                        warn!(
                            content.id = hex_encode(content_id),
                            "Couldn't find corresponding content key in meta db",
                        );
                        continue;
                    }
                    Err(e) => {
                        warn!(
                            content.id = hex_encode(content_id),
                            "Error during lookup of content key in meta db {e}",
                        );
                        continue;
                    }
                };
                let key_hex = hex_encode(&key_bytes);
                let content_key = match HistoryContentKey::try_from(key_bytes) {
                    Ok(key) => key,
                    Err(e) => {
                        warn!(
                            content.key = key_hex,
                            "Could not convert bytes into content key {e}"
                        );
                        continue;
                    }
                };

                if !is_content_valid(&content_key, &value.into_vec()) {
                    match storage.evict(content_id) {
                        Ok(_) => remove_count += 1,
                        Err(err) => warn!(
                            "Error occurred while evicting content key: {key_hex:?} - {err:?}"
                        ),
                    }
                }
            }
        }
    }
    info!("Found {item_count:?} total items - Removed {remove_count:?} items");
    Ok(())
}

fn is_content_valid(content_key: &HistoryContentKey, value: &[u8]) -> bool {
    match content_key {
        HistoryContentKey::BlockHeaderWithProof(_) => {
            HeaderWithProof::from_ssz_bytes(value).is_ok()
        }
        HistoryContentKey::BlockBody(_) => BlockBody::from_ssz_bytes(value).is_ok(),
        HistoryContentKey::BlockReceipts(_) => Receipts::from_ssz_bytes(value).is_ok(),
        HistoryContentKey::EpochAccumulator(_) => EpochAccumulator::from_ssz_bytes(value).is_ok(),
    }
}

// CLI Parameter Handling
#[derive(Parser, Debug, PartialEq)]
#[command(
    name = "Trin DB Purge Util",
    about = "Remove undesired or invalid data from Trin DB"
)]
pub struct PurgeConfig {
    #[arg(
        long,
        help = "(unsafe) Hex private key to generate node id for database namespace (with 0x prefix)"
    )]
    pub private_key: H256,

    #[arg(
        default_value = "all",
        long,
        help = "Purge all content or only invalidly encoded content"
    )]
    pub mode: PurgeMode,
}

#[derive(ValueEnum, Debug, PartialEq, Eq, Clone)]
pub enum PurgeMode {
    All,
    InvalidOnly,
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_default_purge_config() {
        const PRIVATE_KEY: &str =
            "0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let purge_config = PurgeConfig::parse_from(["test", "--private-key", PRIVATE_KEY]);
        assert_eq!(
            purge_config.private_key,
            H256::from_str(PRIVATE_KEY).unwrap()
        );
        assert_eq!(purge_config.mode, PurgeMode::All);
    }

    #[test]
    fn test_purge_mode_with_invalid_only() {
        const PRIVATE_KEY: &str =
            "0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let purge_config = PurgeConfig::parse_from([
            "test",
            "--private-key",
            PRIVATE_KEY,
            "--mode",
            "invalid-only",
        ]);
        assert_eq!(
            purge_config.private_key,
            H256::from_str(PRIVATE_KEY).unwrap()
        );
        assert_eq!(purge_config.mode, PurgeMode::InvalidOnly);
    }
}
