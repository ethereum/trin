use std::sync::Arc;

use parking_lot::RwLock as PLRwLock;
use tokio::sync::RwLock;

use ethportal_api::types::distance::XorMetric;
use ethportal_api::types::enr::Enr;
use ethportal_api::types::portal_wire::ProtocolId;
use ethportal_api::HistoryContentKey;
use portalnet::{
    config::PortalnetConfig,
    discovery::Discovery,
    overlay::{OverlayConfig, OverlayProtocol},
    storage::{PortalStorage, PortalStorageConfig},
    utp_controller::UtpController,
};
use trin_validation::oracle::HeaderOracle;

use crate::validation::ChainHistoryValidator;

/// History network layer on top of the overlay protocol. Encapsulates history network specific data and logic.
#[derive(Clone)]
pub struct HistoryNetwork {
    pub overlay:
        Arc<OverlayProtocol<HistoryContentKey, XorMetric, ChainHistoryValidator, PortalStorage>>,
}

impl HistoryNetwork {
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
            disable_poke: portal_config.disable_poke,
            ..Default::default()
        };
        let storage = Arc::new(PLRwLock::new(PortalStorage::new(
            storage_config,
            ProtocolId::History,
        )?));
        let validator = Arc::new(ChainHistoryValidator { header_oracle });
        let overlay = OverlayProtocol::new(
            config,
            discovery,
            utp_controller,
            storage,
            ProtocolId::History,
            validator,
        )
        .await;

        Ok(Self {
            overlay: Arc::new(overlay),
        })
    }
}
