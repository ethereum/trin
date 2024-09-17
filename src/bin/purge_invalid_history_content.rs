use alloy_primitives::B256;
use anyhow::Result;
use clap::Parser;
use discv5::enr::{CombinedKey, Enr};
use ssz::Decode;
use tracing::info;

use ethportal_api::{
    types::{execution::header_with_proof::HeaderWithProof, portal_wire::ProtocolId},
    BlockBody, HistoryContentKey, OverlayContentKey, Receipts,
};
use portalnet::utils::db::{configure_node_data_dir, configure_trin_data_dir};
use trin_storage::{
    versioned::{create_store, ContentType, IdIndexedV1Store, IdIndexedV1StoreConfig},
    ContentId, PortalStorageConfigFactory,
};
use trin_utils::log::init_tracing_logger;

/// iterates history store and removes any invalid network entries
pub fn main() -> Result<()> {
    init_tracing_logger();
    let script_config = PurgeConfig::parse();

    let trin_data_dir = configure_trin_data_dir(false /* ephemeral */)?;
    let (node_data_dir, mut private_key) = configure_node_data_dir(
        trin_data_dir,
        script_config.private_key,
        "mainnet".to_string(),
    )?;
    let enr_key = CombinedKey::secp256k1_from_bytes(private_key.as_mut_slice())
        .expect("Failed to create ENR key");
    let enr = Enr::empty(&enr_key).unwrap();
    let node_id = enr.node_id();
    info!("Purging data for NodeID: {node_id}");
    info!("DB Path: {node_data_dir:?}");

    let config = PortalStorageConfigFactory::new(
        script_config.capacity as u64,
        &["history".to_string()],
        node_id,
        node_data_dir,
    )
    .unwrap()
    .create("history");
    let config = IdIndexedV1StoreConfig::new(ContentType::History, ProtocolId::History, config);
    let sql_connection_pool = config.sql_connection_pool.clone();
    let mut store: IdIndexedV1Store<HistoryContentKey> =
        create_store(ContentType::History, config, sql_connection_pool).unwrap();

    let total_entry_count = store.usage_stats().entry_count;
    let mut content_ids_to_remove = Vec::new();
    for offset in (0..total_entry_count).step_by(100) {
        let paginate_result = store.paginate(offset, 100)?;
        for key in paginate_result.content_keys {
            let content_id = ContentId::from(key.content_id());
            let value = store.lookup_content_value(&content_id)?;
            if let Some(value) = value {
                if !is_content_valid(&key, &value) {
                    content_ids_to_remove.push(content_id);
                }
            }
        }
    }
    info!(
        "found {} invalid history content values",
        content_ids_to_remove.len()
    );
    if script_config.evict {
        for content_id in &content_ids_to_remove {
            store.delete(content_id)?;
        }
        info!(
            "removed {} invalid history content values",
            content_ids_to_remove.len()
        );
    }
    Ok(())
}

fn is_content_valid(content_key: &HistoryContentKey, value: &[u8]) -> bool {
    match content_key {
        HistoryContentKey::BlockHeaderByHash(_) | HistoryContentKey::BlockHeaderByNumber(_) => {
            HeaderWithProof::from_ssz_bytes(value).is_ok()
        }
        HistoryContentKey::BlockBody(_) => BlockBody::from_ssz_bytes(value).is_ok(),
        HistoryContentKey::BlockReceipts(_) => Receipts::from_ssz_bytes(value).is_ok(),
    }
}

// CLI Parameter Handling
#[derive(Parser, Debug, PartialEq)]
#[command(
    name = "Trin DB Purge Invalid History Content",
    about = "Remove invalid data from Trin History Store"
)]
pub struct PurgeConfig {
    #[arg(
        long,
        help = "(unsafe) Hex private key to generate node id for database namespace (with 0x prefix)"
    )]
    pub private_key: Option<B256>,

    #[arg(
        long,
        help = "Storage capacity. Must be larger than the current capacity otherwise it will prune data!"
    )]
    pub capacity: usize,

    #[arg(
        long,
        help = "Actually evict the history data from db",
        default_value = "false"
    )]
    pub evict: bool,
}
