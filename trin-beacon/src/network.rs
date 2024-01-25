use std::sync::Arc;

use parking_lot::RwLock as PLRwLock;
use tokio::sync::RwLock;

use crate::{storage::BeaconStorage, sync::BeaconSync, validation::BeaconValidator};
use ethportal_api::{
    types::{distance::XorMetric, enr::Enr, portal_wire::ProtocolId},
    BeaconContentKey,
};
use portalnet::{
    config::PortalnetConfig,
    discovery::Discovery,
    overlay::{OverlayConfig, OverlayProtocol},
    utp_controller::UtpController,
};
use trin_storage::PortalStorageConfig;
use trin_validation::oracle::HeaderOracle;

/// Beacon network layer on top of the overlay protocol. Encapsulates beacon network specific data
/// and logic.
#[derive(Clone)]
pub struct BeaconNetwork {
    pub overlay: Arc<OverlayProtocol<BeaconContentKey, XorMetric, BeaconValidator, BeaconStorage>>,
}

impl BeaconNetwork {
    pub async fn new(
        discovery: Arc<Discovery>,
        utp_controller: Arc<UtpController>,
        storage_config: PortalStorageConfig,
        portal_config: PortalnetConfig,
        header_oracle: Arc<RwLock<HeaderOracle>>,
    ) -> anyhow::Result<Self> {
        let bootnode_enrs: Vec<Enr> = portal_config.bootnodes.into();
        let config = OverlayConfig {
            bootnode_enrs,
            ..Default::default()
        };
        let storage = Arc::new(PLRwLock::new(BeaconStorage::new(storage_config)?));
        let validator = Arc::new(BeaconValidator { header_oracle });
        let overlay = OverlayProtocol::new(
            config,
            discovery,
            utp_controller,
            storage,
            ProtocolId::Beacon,
            validator,
        )
        .await;

        let overlay_tx = overlay.command_tx.clone();

        // Spawn the beacon sync task.
        if portal_config.trusted_block_root.is_some() {
            tokio::spawn(async move {
                let beacon_sync = BeaconSync::new(overlay_tx);
                beacon_sync
                    .start(
                        portal_config
                            .trusted_block_root
                            .expect("Trusted block root should be available"),
                    )
                    .await
                    .expect("Beacon sync failed to start");
            });
        }

        Ok(Self {
            overlay: Arc::new(overlay),
        })
    }
}
