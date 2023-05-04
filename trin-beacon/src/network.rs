use std::sync::Arc;

use parking_lot::RwLock as PLRwLock;
use tokio::sync::RwLock;
use utp_rs::socket::UtpSocket;

use crate::validation::BeaconValidator;
use portalnet::{
    discovery::{Discovery, UtpEnr},
    overlay::{OverlayConfig, OverlayProtocol},
    storage::{PortalStorage, PortalStorageConfig},
    types::messages::{PortalnetConfig, ProtocolId},
};
use trin_types::content_key::BeaconContentKey;
use trin_types::distance::XorMetric;
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
        let config = OverlayConfig {
            bootnode_enrs: portal_config.bootnode_enrs.clone(),
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

        Ok(Self {
            overlay: Arc::new(overlay),
        })
    }
}
