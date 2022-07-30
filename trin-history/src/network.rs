use log::{debug, error};
use std::sync::{Arc, RwLock as StdRwLock};

use parking_lot::RwLock;
use tokio::sync::mpsc::UnboundedSender;

use trin_core::{
    portalnet::{
        discovery::Discovery,
        overlay::{OverlayConfig, OverlayProtocol},
        storage::{PortalStorage, PortalStorageConfig},
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
    pub overlay: Arc<OverlayProtocol<HistoryContentKey, XorMetric, ChainHistoryValidator>>,
}

impl HistoryNetwork {
    pub async fn new(
        discovery: Arc<Discovery>,
        utp_listener_tx: UnboundedSender<UtpListenerRequest>,
        storage_config: PortalStorageConfig,
        portal_config: PortalnetConfig,
        header_oracle: Arc<StdRwLock<HeaderOracle>>,
    ) -> Self {
        let config = OverlayConfig {
            bootnode_enrs: portal_config.bootnode_enrs.clone(),
            enable_metrics: portal_config.enable_metrics,
            ..Default::default()
        };
        let storage = Arc::new(RwLock::new(PortalStorage::new(storage_config).unwrap()));
        let validator = Arc::new(ChainHistoryValidator { header_oracle });
        let overlay = OverlayProtocol::new(
            config,
            discovery,
            utp_listener_tx,
            storage,
            portal_config.data_radius,
            ProtocolId::History,
            validator,
        )
        .await;

        Self {
            overlay: Arc::new(overlay),
        }
    }

    /// Convenience call for testing, quick way to ping bootnodes
    pub async fn ping_bootnodes(&self) {
        // Trigger bonding with bootnodes, at both the base layer and portal overlay.
        // The overlay ping via talkreq will trigger a session at the base layer, then
        // a session on the (overlay) portal network.
        let mut successfully_bonded_bootnode = false;
        let enrs = self.overlay.discovery.discv5.table_entries_enr();
        if enrs.is_empty() {
            error!("No bootnodes provided, cannot join Portal History Network.");
            return;
        }
        for enr in enrs {
            debug!("Attempting bond with bootnode {}", enr);
            let ping_result = self.overlay.send_ping(enr.clone()).await;

            match ping_result {
                Ok(_) => {
                    debug!("Successfully bonded with {}", enr);
                    successfully_bonded_bootnode = true;
                }
                Err(err) => {
                    error!("{err} while pinging bootnode: {enr:?}");
                }
            }
        }
        if !successfully_bonded_bootnode {
            error!("Failed to bond with any bootnodes, cannot join Portal History Network.");
        }
    }
}
