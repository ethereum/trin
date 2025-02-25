use std::sync::Arc;

use ethportal_api::{
    types::{distance::XorMetric, network::Subnetwork},
    HistoryContentKey,
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
    ping_extensions::HistoryPingExtensions, storage::HistoryStorage,
    validation::ChainHistoryValidator,
};

/// Gossip content as it gets dropped from local storage,
/// enabled by default for the history network.
const GOSSIP_DROPPED: bool = true;

/// History network layer on top of the overlay protocol. Encapsulates history network specific data
/// and logic.
#[derive(Clone)]
pub struct HistoryNetwork {
    pub overlay: Arc<
        OverlayProtocol<
            HistoryContentKey,
            XorMetric,
            ChainHistoryValidator,
            HistoryStorage,
            HistoryPingExtensions,
        >,
    >,
}

impl HistoryNetwork {
    pub async fn new(
        discovery: Arc<Discovery>,
        utp_socket: Arc<UtpSocket<UtpPeer>>,
        storage_config: PortalStorageConfig,
        portal_config: PortalnetConfig,
        header_oracle: Arc<RwLock<HeaderOracle>>,
        disable_history_storage: bool,
    ) -> anyhow::Result<Self> {
        let config = OverlayConfig {
            bootnode_enrs: portal_config.bootnodes,
            disable_poke: portal_config.disable_poke,
            gossip_dropped: GOSSIP_DROPPED,
            utp_transfer_limit: portal_config.utp_transfer_limit,
            ..Default::default()
        };
        let storage = Arc::new(Mutex::new(HistoryStorage::new(
            storage_config,
            disable_history_storage,
        )?));
        let validator = Arc::new(ChainHistoryValidator { header_oracle });
        let ping_extensions = Arc::new(HistoryPingExtensions {});
        let overlay = OverlayProtocol::new(
            config,
            discovery,
            utp_socket,
            storage,
            Subnetwork::History,
            validator,
            ping_extensions,
        )
        .await;

        Ok(Self {
            overlay: Arc::new(overlay),
        })
    }
}
