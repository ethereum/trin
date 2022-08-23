use std::sync::{Arc, RwLock as StdRwLock};

use parking_lot::RwLock;
use tokio::sync::mpsc::UnboundedSender;

use trin_core::{
    portalnet::{
        discovery::Discovery,
        overlay::{OverlayConfig, OverlayProtocol},
        storage::{PortalStore, PortalStoreConfig},
        types::{
            content_key::HistoryContentKey,
            messages::{PortalnetConfig, ProtocolId},
            metric::XorMetric,
        },
    },
    types::validation::HeaderOracle,
    utp::stream::UtpListenerRequest,
};

use crate::validation::ChainHistoryValidator;

/// History network layer on top of the overlay protocol. Encapsulates history network specific data and logic.
#[derive(Clone)]
pub struct HistoryNetwork {
    pub overlay:
        Arc<OverlayProtocol<HistoryContentKey, XorMetric, ChainHistoryValidator, PortalStore>>,
}

impl HistoryNetwork {
    pub async fn new(
        discovery: Arc<Discovery>,
        utp_listener_tx: UnboundedSender<UtpListenerRequest>,
        store_config: PortalStoreConfig,
        portal_config: PortalnetConfig,
        header_oracle: Arc<StdRwLock<HeaderOracle>>,
    ) -> Self {
        let config = OverlayConfig {
            bootnode_enrs: portal_config.bootnode_enrs.clone(),
            enable_metrics: portal_config.enable_metrics,
            ..Default::default()
        };
        let store = Arc::new(RwLock::new(PortalStore::new(store_config).unwrap()));
        let validator = Arc::new(ChainHistoryValidator { header_oracle });
        let overlay = OverlayProtocol::new(
            config,
            discovery,
            utp_listener_tx,
            store,
            portal_config.data_radius,
            ProtocolId::History,
            validator,
        )
        .await;

        Self {
            overlay: Arc::new(overlay),
        }
    }
}
