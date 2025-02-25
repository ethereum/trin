use std::sync::Arc;

use ethportal_api::{
    types::{distance::XorMetric, network::Subnetwork},
    StateContentKey,
};
use parking_lot::Mutex;
use portalnet::{
    config::PortalnetConfig,
    discovery::{Discovery, UtpPeer},
    overlay::{config::OverlayConfig, protocol::OverlayProtocol},
};
use tokio::sync::RwLock;
use tracing::debug;
use trin_storage::PortalStorageConfig;
use trin_validation::oracle::HeaderOracle;
use utp_rs::socket::UtpSocket;

use crate::{
    ping_extensions::StatePingExtensions, storage::StateStorage, validation::StateValidator,
};

/// State network layer on top of the overlay protocol. Encapsulates state network specific data and
/// logic.
#[derive(Clone)]
pub struct StateNetwork {
    pub overlay: Arc<
        OverlayProtocol<
            StateContentKey,
            XorMetric,
            StateValidator,
            StateStorage,
            StatePingExtensions,
        >,
    >,
}

/// Poke is disabled for state network because Offer/Accept and Find/Found Content are different,
/// and recipient of the poke wouldn't be able to verify that content is canonical.
const DISABLE_POKE: bool = true;
/// Gossiping content as it gets dropped from local storage is disabled for the state network,
/// since data as it's stored locally doesn't contain the proofs needed to verify the gossiped data.
const GOSSIP_DROPPED: bool = false;

impl StateNetwork {
    pub async fn new(
        discovery: Arc<Discovery>,
        utp_socket: Arc<UtpSocket<UtpPeer>>,
        storage_config: PortalStorageConfig,
        portal_config: PortalnetConfig,
        header_oracle: Arc<RwLock<HeaderOracle>>,
    ) -> anyhow::Result<Self> {
        if !portal_config.disable_poke {
            debug!("Poke is not supported by the State Network")
        }
        let config = OverlayConfig {
            bootnode_enrs: portal_config.bootnodes,
            disable_poke: DISABLE_POKE,
            gossip_dropped: GOSSIP_DROPPED,
            utp_transfer_limit: portal_config.utp_transfer_limit,
            ..Default::default()
        };
        let storage = Arc::new(Mutex::new(StateStorage::new(storage_config)?));
        let validator = Arc::new(StateValidator { header_oracle });
        let ping_extensions = Arc::new(StatePingExtensions {});
        let overlay = OverlayProtocol::new(
            config,
            discovery,
            utp_socket,
            storage,
            Subnetwork::State,
            validator,
            ping_extensions,
        )
        .await;

        Ok(Self {
            overlay: Arc::new(overlay),
        })
    }
}
