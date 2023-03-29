use std::sync::Arc;

use parking_lot::RwLock as PLRwLock;
use tokio::sync::RwLock;
use utp_rs::socket::UtpSocket;

use ethportal_api::HistoryContentKey;
use portalnet::{
    discovery::{Discovery, UtpEnr},
    overlay::{OverlayConfig, OverlayProtocol},
    storage::{PortalStorage, PortalStorageConfig},
    types::messages::{PortalnetConfig, ProtocolId},
};
use trin_types::distance::XorMetric;
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
        utp_socket: Arc<UtpSocket<UtpEnr>>,
        storage_config: PortalStorageConfig,
        portal_config: PortalnetConfig,
        header_oracle: Arc<RwLock<HeaderOracle>>,
    ) -> anyhow::Result<Self> {
        let config = OverlayConfig {
            bootnode_enrs: portal_config.bootnode_enrs.clone(),
            enable_metrics: portal_config.enable_metrics,
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
            utp_socket,
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
