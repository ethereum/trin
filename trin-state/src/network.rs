use log::debug;
use rocksdb::DB;
use std::sync::Arc;
use tokio::sync::RwLock;
use trin_core::portalnet::{
    discovery::Discovery,
    overlay::{OverlayConfig, OverlayProtocol},
    types::{PortalnetConfig, ProtocolKind},
    U256,
};

/// State network layer on top of the overlay protocol. Encapsulates state network specific data and logic.
#[derive(Clone)]
pub struct StateNetwork {
    pub overlay: Arc<OverlayProtocol>,
}

impl StateNetwork {
    pub async fn new(
        discovery: Arc<RwLock<Discovery>>,
        db: Arc<DB>,
        portal_config: PortalnetConfig,
    ) -> Self {
        let config = OverlayConfig::default();
        let overlay = OverlayProtocol::new(config, discovery, db, portal_config.data_radius).await;

        Self {
            overlay: Arc::new(overlay),
        }
    }

    /// Convenience call for testing, quick way to ping bootnodes
    pub async fn ping_bootnodes(&mut self) -> Result<(), String> {
        // Trigger bonding with bootnodes, at both the base layer and portal overlay.
        // The overlay ping via talkreq will trigger a session at the base layer, then
        // a session on the (overlay) portal network.
        for enr in self
            .overlay
            .discovery
            .read()
            .await
            .discv5
            .table_entries_enr()
        {
            debug!("Pinging {} on portal state network", enr);
            let ping_result = self
                .overlay
                .send_ping(U256::from(u64::MAX), enr, ProtocolKind::State, None)
                .await?;
            debug!("Portal state network Ping result: {:?}", ping_result);
        }
        Ok(())
    }
}
