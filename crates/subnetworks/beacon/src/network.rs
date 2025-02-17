use std::sync::Arc;

use alloy::primitives::B256;
use ethportal_api::{
    types::{distance::XorMetric, network::Subnetwork},
    BeaconContentKey,
};
use light_client::{consensus::rpc::portal_rpc::PortalRpc, database::FileDB, Client};
use parking_lot::RwLock as PLRwLock;
use portalnet::{
    config::PortalnetConfig,
    discovery::{Discovery, UtpPeer},
    overlay::{config::OverlayConfig, protocol::OverlayProtocol},
};
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info};
use trin_storage::PortalStorageConfig;
use trin_validation::oracle::HeaderOracle;
use utp_rs::socket::UtpSocket;

use crate::{
    ping_extensions::BeaconPingExtensions, storage::BeaconStorage, sync::BeaconSync,
    validation::BeaconValidator,
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
    ) -> anyhow::Result<Self> {
        let config = OverlayConfig {
            bootnode_enrs: portal_config.bootnodes,
            utp_transfer_limit: portal_config.utp_transfer_limit,
            gossip_dropped: GOSSIP_DROPPED,
            ..Default::default()
        };
        let storage = Arc::new(PLRwLock::new(BeaconStorage::new(storage_config)?));
        storage.write().spawn_pruning_task(); // Spawn pruning task to clean up expired content.
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

        // Spawn the beacon sync task.
        let trusted_block_root: Option<B256> = match portal_config.trusted_block_root {
            Some(trusted_block_root) => Some(trusted_block_root),
            None => {
                // If no trusted block root is provided, we check for the latest block root in the
                // database.
                let block_root = storage_clone.read().lookup_latest_block_root()?;
                if let Some(block_root) = block_root {
                    info!(block_root = %block_root, "No trusted block root provided. Using latest block root from storage.");
                }
                block_root
            }
        };

        if let Some(trusted_block_root) = trusted_block_root {
            tokio::spawn(async move {
                let beacon_sync = BeaconSync::new(overlay_tx);
                let beacon_sync = beacon_sync.start(trusted_block_root).await;
                match beacon_sync {
                    Ok(client) => {
                        let mut beacon_client = beacon_client_clone.lock().await;
                        *beacon_client = Some(client);
                    }
                    Err(err) => {
                        error!(error = %err, "Failed to start beacon sync.");
                    }
                }
            });
        }

        Ok(Self {
            overlay: Arc::new(overlay),
            beacon_client,
        })
    }
}
