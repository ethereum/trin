use parking_lot::RwLock as PLRwLock;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::storage::StateStorage;
use ethportal_api::{
    types::{distance::XorMetric, portal_wire::ProtocolId},
    StateContentKey,
};
use portalnet::{
    config::PortalnetConfig,
    discovery::Discovery,
    overlay::{OverlayConfig, OverlayProtocol},
    utp_controller::UtpController,
};
use trin_validation::oracle::HeaderOracle;

use crate::validation::StateValidator;
use trin_storage::PortalStorageConfig;

/// State network layer on top of the overlay protocol. Encapsulates state network specific data and
/// logic.
#[derive(Clone)]
pub struct StateNetwork {
    pub overlay: Arc<OverlayProtocol<StateContentKey, XorMetric, StateValidator, StateStorage>>,
}

impl StateNetwork {
    pub async fn new(
        discovery: Arc<Discovery>,
        utp_controller: Arc<UtpController>,
        storage_config: PortalStorageConfig,
        portal_config: PortalnetConfig,
        header_oracle: Arc<RwLock<HeaderOracle>>,
    ) -> anyhow::Result<Self> {
        let config = OverlayConfig {
            bootnode_enrs: portal_config.bootnodes.into(),
            disable_poke: portal_config.disable_poke,
            ..Default::default()
        };
        let storage = Arc::new(PLRwLock::new(StateStorage::new(
            storage_config,
            ProtocolId::State,
        )?));
        let validator = Arc::new(StateValidator { header_oracle });
        let overlay = OverlayProtocol::new(
            config,
            discovery,
            utp_controller,
            storage,
            ProtocolId::State,
            validator,
        )
        .await;

        Ok(Self {
            overlay: Arc::new(overlay),
        })
    }
}
