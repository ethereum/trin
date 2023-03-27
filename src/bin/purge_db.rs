use std::str::FromStr;

use anyhow::{anyhow, Result};
use discv5::enr::{CombinedKey, EnrBuilder};
use ethereum_types::H256;
use rocksdb::IteratorMode;
use ssz::Decode;
use structopt::StructOpt;
use tracing::{info, warn};

use ethportal_api::HistoryContentKey;
use portalnet::storage::{PortalStorage, PortalStorageConfig};
use portalnet::types::messages::ProtocolId;
use portalnet::utils::db::get_data_dir;
use trin_types::execution::accumulator::EpochAccumulator;
use trin_types::execution::block_body::BlockBody;
use trin_types::execution::header::HeaderWithProof;
use trin_types::execution::receipts::Receipts;
use trin_utils::bytes::hex_encode;

///
/// This script will iterate through all content id / key pairs in rocksd & meta db.
/// However, if it is run in "invalid-only" mode, it will error if it encounters any
/// non-history network content. Since we only support history network content, this
/// shouldn't be a problem, but as we add support for more sub-networks this script will
/// need to be updated to avoid panicking.
///
pub fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let purge_config = PurgeConfig::from_args();

    let enr_key =
        CombinedKey::secp256k1_from_bytes(&mut purge_config.private_key.to_fixed_bytes()).unwrap();
    let enr = EnrBuilder::new("v4").build(&enr_key).unwrap();
    let node_id = enr.node_id();
    let data_dir_path = get_data_dir(node_id);
    info!("Purging data for NodeID: {}", node_id);
    info!("DB Path: {:?}", data_dir_path);

    // Capacity is 0 since it (eg. for data radius calculation) is irrelevant when only removing data.
    let capacity = 0;
    let protocol = ProtocolId::History;
    let config = PortalStorageConfig::new(capacity, node_id, false)?;
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
                Err(err) => warn!(
                    "Error occurred while evicting content id: {:?} - {:?}",
                    content_id, err
                ),
            },
            PurgeMode::Invalid => {
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
                            "Error occurred while evicting content key: {:?} - {:?}",
                            key_hex, err
                        ),
                    }
                }
            }
        }
    }
    info!(
        "Found {:?} total items - Removed {:?} items",
        item_count, remove_count
    );
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
#[derive(StructOpt, Debug, PartialEq)]
#[structopt(
    name = "Trin DB Purge Util",
    about = "Remove undesired or invalid data from Trin DB"
)]
pub struct PurgeConfig {
    #[structopt(
        long,
        help = "(unsafe) Hex private key to generate node id for database namespace (with 0x prefix)"
    )]
    pub private_key: H256,

    #[structopt(
        default_value = "all",
        possible_values(&["all", "invalid-only"]),
        long,
        help = "Purge all content or only invalidly encoded content"
    )]
    pub mode: PurgeMode,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PurgeMode {
    All,
    Invalid,
}

impl FromStr for PurgeMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        match s {
            "all" => Ok(Self::All),
            "invalid-only" => Ok(Self::Invalid),
            _ => Err(anyhow!(
                "Invalid purge mode provided. Possible values include `all` and `invalid-only`"
            )),
        }
    }
}
