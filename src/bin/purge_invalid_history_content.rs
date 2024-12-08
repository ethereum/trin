use alloy::primitives::B256;
use anyhow::Result;
use clap::Parser;
use discv5::enr::{CombinedKey, Enr};
use ethportal_api::types::{
    cli::StorageCapacityConfig,
    network::{Network, Subnetwork},
};
use portalnet::utils::db::{configure_node_data_dir, configure_trin_data_dir};
use tracing::info;
use trin_storage::{
    versioned::{ContentType, IdIndexedV1StoreConfig},
    PortalStorageConfigFactory,
};
use trin_utils::log::init_tracing_logger;

/// iterates history store and removes any invalid network entries
pub fn main() -> Result<()> {
    init_tracing_logger();
    let script_config = PurgeConfig::parse();

    let trin_data_dir =
        configure_trin_data_dir(None /* data_dir */, false /* ephemeral */)?;
    let (node_data_dir, mut private_key) =
        configure_node_data_dir(&trin_data_dir, script_config.private_key, Network::Mainnet)?;
    let enr_key = CombinedKey::secp256k1_from_bytes(private_key.as_mut_slice())
        .expect("Failed to create ENR key");
    let enr = Enr::empty(&enr_key).unwrap();
    let node_id = enr.node_id();
    info!("Purging data for NodeID: {node_id}");
    info!("DB Path: {node_data_dir:?}");

    let config = PortalStorageConfigFactory::new(
        StorageCapacityConfig::Combined {
            total_mb: script_config.capacity as u32,
            subnetworks: vec![Subnetwork::History],
        },
        node_id,
        node_data_dir,
    )
    .unwrap()
    .create(&Subnetwork::History)
    .unwrap();
    let config = IdIndexedV1StoreConfig::new(ContentType::History, Subnetwork::History, config);
    let sql_connection_pool = config.sql_connection_pool.clone();
    let total_count = sql_connection_pool
        .get()
        .unwrap()
        .query_row(&lookup_all_query(), [], |row| row.get::<usize, u64>(0))
        .expect("Failed to lookup history content");
    info!("total entry count: {total_count}");
    let lookup_result = sql_connection_pool
        .get()
        .unwrap()
        .query_row(&lookup_epoch_acc_query(), [], |row| {
            row.get::<usize, u64>(0)
        })
        .expect("Failed to fetch history content");
    info!("found {} epoch accumulators", lookup_result);
    if script_config.evict {
        let removed_count = sql_connection_pool
            .get()
            .unwrap()
            .execute(&delete_epoch_acc_query(), [])
            .unwrap();
        info!("removed {} invalid history content values", removed_count);
    }
    Ok(())
}

fn lookup_all_query() -> String {
    r#"SELECT COUNT(*) as count FROM ii1_history"#.to_string()
}

fn lookup_epoch_acc_query() -> String {
    r#"SELECT COUNT(*) as count FROM ii1_history WHERE hex(content_key) LIKE "03%""#.to_string()
}

fn delete_epoch_acc_query() -> String {
    r#"DELETE FROM ii1_history WHERE hex(content_key) LIKE '03%'"#.to_string()
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
