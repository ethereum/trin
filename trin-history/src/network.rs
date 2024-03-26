use std::sync::Arc;

use parking_lot::RwLock as PLRwLock;
use tokio::sync::RwLock;
use utp_rs::socket::UtpSocket;

use crate::storage::HistoryStorage;
use ethportal_api::{
    types::{distance::XorMetric, enr::Enr, portal_wire::ProtocolId},
    HistoryContentKey,
};
use portalnet::{
    config::PortalnetConfig,
    discovery::{Discovery, UtpEnr},
    overlay::{config::OverlayConfig, protocol::OverlayProtocol},
};
use trin_validation::oracle::HeaderOracle;

use crate::validation::ChainHistoryValidator;
use trin_storage::PortalStorageConfig;

/// History network layer on top of the overlay protocol. Encapsulates history network specific data
/// and logic.
#[derive(Clone)]
pub struct HistoryNetwork {
    pub overlay:
        Arc<OverlayProtocol<HistoryContentKey, XorMetric, ChainHistoryValidator, HistoryStorage>>,
}

impl HistoryNetwork {
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
            disable_poke: portal_config.disable_poke,
            utp_transfer_limit: portal_config.utp_transfer_limit,
            ..Default::default()
        };
        let storage = Arc::new(PLRwLock::new(HistoryStorage::new(storage_config)?));
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
