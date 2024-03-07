use parking_lot::RwLock as PLRwLock;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;
use utp_rs::socket::UtpSocket;

use crate::storage::StateStorage;
use ethportal_api::{
    types::{distance::XorMetric, portal_wire::ProtocolId},
    StateContentKey,
};
use portalnet::{
    config::PortalnetConfig,
    discovery::{Discovery, UtpEnr},
    overlay::{config::OverlayConfig, protocol::OverlayProtocol},
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

/// Poke is disabled for state network because Offer/Accept and Find/Found Content are different,
/// and recipient of the poke wouldn't be able to verify that content is canonical.
const DISABLE_POKE: bool = true;

impl StateNetwork {
    pub async fn new(
        discovery: Arc<Discovery>,
        utp_socket: Arc<UtpSocket<UtpEnr>>,
        storage_config: PortalStorageConfig,
        portal_config: PortalnetConfig,
        header_oracle: Arc<RwLock<HeaderOracle>>,
    ) -> anyhow::Result<Self> {
        if !portal_config.disable_poke {
            debug!("Poke is not supported by the State Network")
        }
        let config = OverlayConfig {
            bootnode_enrs: portal_config.bootnodes.into(),
            disable_poke: DISABLE_POKE,
            utp_transfer_limit: portal_config.utp_transfer_limit,
            ..Default::default()
        };
        let storage = Arc::new(PLRwLock::new(StateStorage::new(storage_config)?));
        let validator = Arc::new(StateValidator { header_oracle });
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
