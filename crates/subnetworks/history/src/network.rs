use std::sync::Arc;

use ethportal_api::{
    types::{distance::XorMetric, network::Subnetwork},
    LegacyHistoryContentKey,
};
use parking_lot::Mutex;
use portalnet::{
    config::PortalnetConfig,
    discovery::{Discovery, UtpPeer},
    overlay::{config::OverlayConfig, protocol::OverlayProtocol},
};
use tokio::sync::RwLock;
use trin_storage::PortalStorageConfig;
use trin_validation::oracle::HeaderOracle;
use utp_rs::socket::UtpSocket;

use crate::{
    ping_extensions::LegacyHistoryPingExtensions, storage::LegacyHistoryStorage,
    validation::LegacyHistoryValidator,
};

/// Gossip content as it gets dropped from local storage,
/// enabled by default for the history network.
const GOSSIP_DROPPED: bool = true;

/// Legacy History network layer on top of the overlay protocol. Encapsulates legacy history
/// network specific data and logic.
#[derive(Clone)]
pub struct LegacyHistoryNetwork {
    pub overlay: Arc<
        OverlayProtocol<
            LegacyHistoryContentKey,
            XorMetric,
            LegacyHistoryValidator,
            LegacyHistoryStorage,
            LegacyHistoryPingExtensions,
        >,
    >,
}

impl LegacyHistoryNetwork {
    pub async fn new(
        discovery: Arc<Discovery>,
        utp_socket: Arc<UtpSocket<UtpPeer>>,
        storage_config: PortalStorageConfig,
        portal_config: PortalnetConfig,
        header_oracle: Arc<RwLock<HeaderOracle>>,
    ) -> anyhow::Result<Self> {
        let config = OverlayConfig {
            bootnode_enrs: portal_config.bootnodes,
            disable_poke: portal_config.disable_poke,
            gossip_dropped: GOSSIP_DROPPED,
            utp_transfer_limit: portal_config.utp_transfer_limit,
            ..Default::default()
        };
        let storage = Arc::new(Mutex::new(LegacyHistoryStorage::new(storage_config)?));
        let validator = Arc::new(LegacyHistoryValidator::new(header_oracle));
        let ping_extensions = Arc::new(LegacyHistoryPingExtensions {});
        let overlay = OverlayProtocol::new(
            config,
            discovery,
            utp_socket,
            storage,
            Subnetwork::LegacyHistory,
            validator,
            ping_extensions,
        )
        .await;

        Ok(Self {
            overlay: Arc::new(overlay),
        })
    }
}
