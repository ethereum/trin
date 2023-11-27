use std::sync::Arc;

use parking_lot::RwLock as PLRwLock;
use tokio::sync::RwLock;
use utp_rs::socket::UtpSocket;

use crate::validation::BeaconValidator;
use ethportal_api::types::distance::XorMetric;
use ethportal_api::types::enr::Enr;
use ethportal_api::types::portal_wire::ProtocolId;
use ethportal_api::BeaconContentKey;
use portalnet::{
    config::PortalnetConfig,
    discovery::{Discovery, UtpEnr},
    overlay::{OverlayConfig, OverlayProtocol},
    storage::{PortalStorage, PortalStorageConfig},
};
use trin_validation::oracle::HeaderOracle;

/// Beacon network layer on top of the overlay protocol. Encapsulates beacon network specific data and logic.
#[derive(Clone)]
pub struct BeaconNetwork {
    pub overlay: Arc<OverlayProtocol<BeaconContentKey, XorMetric, BeaconValidator, PortalStorage>>,
}

impl BeaconNetwork {
    pub async fn new(
        discovery: Arc<Discovery>,
        utp_socket: Arc<UtpSocket<UtpEnr>>,
        storage_config: PortalStorageConfig,
        portal_config: PortalnetConfig,
        header_oracle: Arc<RwLock<HeaderOracle>>,
    ) -> anyhow::Result<Self> {
        let bootnode_enrs: Vec<Enr> = portal_config.bootnodes.into();
        let config = OverlayConfig {
            bootnode_enrs,
            ..Default::default()
        };
        let storage = Arc::new(PLRwLock::new(PortalStorage::new(
            storage_config,
            ProtocolId::Beacon,
        )?));
        let validator = Arc::new(BeaconValidator { header_oracle });
        let overlay = OverlayProtocol::new(
            config,
            discovery,
            utp_socket,
            storage,
            ProtocolId::Beacon,
            validator,
        )
        .await;

        let _ = overlay.event_stream().await?;

        Ok(Self {
            overlay: Arc::new(overlay),
        })
    }
}
