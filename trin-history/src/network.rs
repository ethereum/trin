use log::debug;
use rocksdb::DB;
use std::sync::Arc;
use tokio::sync::RwLock;
use trin_core::portalnet::{
    discovery::Discovery,
    overlay::{OverlayConfig, OverlayProtocol},
    types::messages::{PortalnetConfig, ProtocolId},
};
use trin_core::utp::stream::UtpListener;

/// History network layer on top of the overlay protocol. Encapsulates history network specific data and logic.
#[derive(Clone)]
pub struct HistoryNetwork {
    pub overlay: Arc<OverlayProtocol>,
}

impl HistoryNetwork {
    pub async fn new(
        discovery: Arc<Discovery>,
        utp_listener: Arc<RwLock<UtpListener>>,
        db: Arc<DB>,
        portal_config: PortalnetConfig,
    ) -> Self {
        let config = OverlayConfig {
            bootnode_enrs: portal_config.bootnode_enrs.clone(),
            ..Default::default()
        };
        let overlay = OverlayProtocol::new(
            config,
            discovery,
            utp_listener,
            db,
            portal_config.data_radius,
            ProtocolId::History,
        )
        .await;

        Self {
            overlay: Arc::new(overlay),
        }
    }

    /// Convenience call for testing, quick way to ping bootnodes
    pub async fn ping_bootnodes(&self) -> anyhow::Result<()> {
        // Trigger bonding with bootnodes, at both the base layer and portal overlay.
        // The overlay ping via talkreq will trigger a session at the base layer, then
        // a session on the (overlay) portal network.
        for enr in self.overlay.discovery.discv5.table_entries_enr() {
            debug!("Pinging {} on portal history network", enr);
            let ping_result = self.overlay.send_ping(enr.clone()).await;

            match ping_result {
                Ok(_) => {
                    debug!("Successfully bonded with {}", enr);
                    continue;
                }
                // Tbh I'm a bit stumped on how to handle this area, so this is just a temporary
                // solution to get the compiler passing. Will revisit if we decide to continue with
                // anyhow
                Err(msg) => {
                    debug!("{}", msg);
                    continue;
                }
            }
        }
        Ok(())
    }
}
