use parking_lot::RwLock as PLRwLock;
use std::sync::Arc;
use tokio::sync::RwLock;
use utp_rs::socket::UtpSocket;

use crate::storage::StateStorage;
use ethportal_api::{
    types::{distance::XorMetric, enr::Enr, portal_wire::ProtocolId},
    StateContentKey,
};
use portalnet::{
    config::PortalnetConfig,
    discovery::{Discovery, UtpEnr},
    overlay::{OverlayConfig, OverlayProtocol},
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
        utp_socket: Arc<UtpSocket<UtpEnr>>,
        storage_config: PortalStorageConfig,
        portal_config: PortalnetConfig,
        header_oracle: Arc<RwLock<HeaderOracle>>,
    ) -> anyhow::Result<Self> {
        let storage = Arc::new(PLRwLock::new(StateStorage::new(
            storage_config,
            ProtocolId::State,
        )?));
        let validator = Arc::new(StateValidator { header_oracle });
        let bootnode_enrs: Vec<Enr> = portal_config.bootnodes.into();
        let config = OverlayConfig {
            bootnode_enrs,
            ..Default::default()
        };
        let overlay = OverlayProtocol::new(
            config,
            discovery,
            utp_socket,
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
