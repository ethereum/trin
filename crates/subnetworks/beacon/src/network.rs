use std::{str::FromStr, sync::Arc, time::SystemTime};

use alloy::primitives::B256;
use anyhow::anyhow;
use ethportal_api::{
    consensus::constants::SECONDS_PER_SLOT,
    types::{distance::XorMetric, network::Subnetwork, network_spec::network_spec},
    BeaconContentKey,
};
use light_client::{consensus::rpc::portal_rpc::PortalRpc, database::FileDB, Client};
use parking_lot::Mutex as PLMutex;
use portalnet::{
    config::PortalnetConfig,
    discovery::{Discovery, UtpPeer},
    overlay::{config::OverlayConfig, protocol::OverlayProtocol},
};
use tokio::{
    sync::{Mutex, RwLock},
    time::{interval_at, Instant, Interval},
};
use tracing::{error, info};
use trin_metrics::chain_head::ChainHeadMetricsReporter;
use trin_storage::PortalStorageConfig;
use trin_validation::{chain_head::ChainHead, oracle::HeaderOracle};
use utp_rs::socket::UtpSocket;

use crate::{
    ping_extensions::BeaconPingExtensions, storage::BeaconStorage, sync::BeaconSync,
    validation::BeaconValidator, DEFAULT_TRUSTED_BLOCK_ROOT,
};

/// Beacon network layer on top of the overlay protocol. Encapsulates beacon network specific data
/// and logic.
#[derive(Clone)]
pub struct BeaconNetwork {
    pub overlay: Arc<
        OverlayProtocol<
            BeaconContentKey,
            XorMetric,
            BeaconValidator,
            BeaconStorage,
            BeaconPingExtensions,
        >,
    >,
    pub beacon_client: Arc<Mutex<Option<Client<FileDB, PortalRpc>>>>,
}

/// Gossiping content as it gets dropped from local storage is disabled for the beacon network,
/// since beacon nodes already store all the content they're interested in.
const GOSSIP_DROPPED: bool = false;

impl BeaconNetwork {
    pub async fn new(
        discovery: Arc<Discovery>,
        utp_socket: Arc<UtpSocket<UtpPeer>>,
        storage_config: PortalStorageConfig,
        portal_config: PortalnetConfig,
        header_oracle: Arc<RwLock<HeaderOracle>>,
        chain_head: ChainHead,
    ) -> anyhow::Result<Self> {
        let config = OverlayConfig {
            bootnode_enrs: portal_config.bootnodes.clone(),
            utp_transfer_limit: portal_config.utp_transfer_limit,
            gossip_dropped: GOSSIP_DROPPED,
            ..Default::default()
        };
        let storage = Arc::new(PLMutex::new(BeaconStorage::new(
            storage_config,
            chain_head.clone(),
        )?));
        storage.lock().spawn_pruning_task(); // Spawn pruning task to clean up expired content.
        let storage_clone = Arc::clone(&storage);
        let validator = Arc::new(BeaconValidator::new(header_oracle));
        let ping_extensions = Arc::new(BeaconPingExtensions {});
        let overlay = OverlayProtocol::new(
            config,
            discovery,
            utp_socket,
            storage,
            Subnetwork::Beacon,
            validator,
            ping_extensions,
        )
        .await;

        let overlay_tx = overlay.command_tx.clone();
        let beacon_client = Arc::new(Mutex::new(None));
        let beacon_client_clone = Arc::clone(&beacon_client);

        // Get the trusted block root to start syncing from.
        let trusted_block_root = get_trusted_block_root(&portal_config, storage_clone)?;

        // Spawn light client sync and update watch task
        tokio::spawn(async move {
            // Sync LightClient
            let client = match BeaconSync::new(overlay_tx).start(trusted_block_root).await {
                Ok(client) => client,
                Err(err) => {
                    error!(error = %err, "Failed to start beacon sync.");
                    return;
                }
            };
            let mut watch_receivers = client.get_light_client_watch_receivers().await;
            *beacon_client_clone.lock().await = Some(client);

            // Update ChainHeadMetrics at every slot timestamp
            let metrics = ChainHeadMetricsReporter::new();
            let mut slot_internal = get_slot_interval();

            // Watch for light clients updates and update ChainHead
            loop {
                tokio::select! {
                    _ = slot_internal.tick() => {
                        metrics.on_slot(network_spec().current_slot());
                    }
                    Ok(()) = watch_receivers.update.changed() => {
                        let update = watch_receivers
                            .update
                            .borrow_and_update()
                            .as_ref()
                            .expect("Updated LightClientUpdate must be present")
                            .clone();
                        chain_head.process_update(update);
                    }
                    Ok(()) = watch_receivers.optimistic_update.changed() => {
                        let update = watch_receivers
                            .optimistic_update
                            .borrow_and_update()
                            .as_ref()
                            .expect("Updated LightClientOptimisticUpdate must be present")
                            .clone();
                        chain_head.process_optimistic_update(update);
                    }
                    Ok(()) = watch_receivers.finality_update.changed() => {
                        let update = watch_receivers
                            .finality_update
                            .borrow_and_update()
                            .as_ref()
                            .expect("Updated LightClientFinalityUpdate must be present")
                            .clone();
                        chain_head.process_finality_update(update);
                    }
                }
            }
        });

        Ok(Self {
            overlay: Arc::new(overlay),
            beacon_client,
        })
    }
}

/// Get the trusted block root to start syncing light client from.
fn get_trusted_block_root(
    portal_config: &PortalnetConfig,
    storage: Arc<PLMutex<BeaconStorage>>,
) -> anyhow::Result<B256> {
    // 1) Check if a trusted block root was provided via config
    if let Some(block_root) = portal_config.trusted_block_root {
        return Ok(block_root);
    }

    // 2) Otherwise, try to read the latest block root from storage
    let maybe_db_block_root = storage.lock().lookup_latest_block_root()?;
    if let Some(db_block_root) = maybe_db_block_root {
        info!(
            block_root = %db_block_root,
            "No trusted block root provided. Using latest block root from storage."
        );
        return Ok(db_block_root);
    }

    // 3) If there's still nothing, log and attempt to load the default checkpoint file
    info!("No trusted block root provided and no block root found in storage. Loading default checkpoint.");
    get_default_trusted_root()
}

/// Get the default trusted block root from the embedded file.
fn get_default_trusted_root() -> anyhow::Result<B256> {
    B256::from_str(DEFAULT_TRUSTED_BLOCK_ROOT.trim())
        .map_err(|err| anyhow!("Failed to parse trusted block root: {err}"))
}

/// Returns the [Interval] that ticks on every slot timestamp.
fn get_slot_interval() -> Interval {
    let now = SystemTime::now();
    let next_slot = network_spec().current_slot() + 1;
    let next_slot_timestamp = network_spec().slot_to_timestamp(next_slot);
    let until_next_slot = next_slot_timestamp
        .duration_since(now)
        .expect("Next slot must be in the future");
    interval_at(Instant::now() + until_next_slot, SECONDS_PER_SLOT)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use discv5::enr::NodeId;
    use ethportal_api::{types::distance::Distance, utils::bytes::hex_decode};
    use tempfile::TempDir;
    use trin_storage::{config::StorageCapacityConfig, PortalStorageConfigFactory};

    use super::*;

    /// Test that embedded "trusted_block_root.txt" can be loaded & parsed into bytes.
    #[test]
    fn test_embedded_trusted_block_root_parsing() {
        let block_root =
            get_default_trusted_root().expect("Failed to parse embedded trusted block root");

        assert_eq!(
            block_root.as_slice(),
            hex_decode(DEFAULT_TRUSTED_BLOCK_ROOT.trim()).expect("Failed to decode hex")
        )
    }

    /// Test to ensure `get_trusted_block_root` falls back to the embedded file
    /// if the config and storage are both empty.
    #[test]
    fn test_get_trusted_block_root_fallback_to_file() {
        let portal_config = PortalnetConfig {
            trusted_block_root: None,
            ..Default::default()
        };
        let temp_dir = TempDir::new().unwrap();
        let storage_cfg_factory = PortalStorageConfigFactory::new(
            StorageCapacityConfig::Specific {
                beacon_mb: Some(1),
                legacy_history_mb: Some(1),
                state_mb: Some(1),
            },
            NodeId::random(),
            temp_dir.path().to_path_buf(),
        )
        .unwrap();
        let storage_config = storage_cfg_factory
            .create(&Subnetwork::Beacon, Distance::MAX)
            .unwrap();

        // A mock storage that always returns None
        let storage_clone = Arc::new(PLMutex::new(
            BeaconStorage::new(storage_config, ChainHead::new_pectra_defaults()).unwrap(),
        ));

        let result = get_trusted_block_root(&portal_config, storage_clone)
            .expect("Function should not fail with an Err");

        assert_eq!(
            result.as_slice(),
            hex_decode(DEFAULT_TRUSTED_BLOCK_ROOT.trim()).expect("Failed to decode hex")
        );

        temp_dir.close().unwrap();
    }
}
