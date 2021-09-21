use discv5::kbucket::KBucketsTable;
use log::debug;
use std::sync::Arc;
use tokio::sync::RwLock;
use trin_core::portalnet::{
    discovery::Discovery,
    overlay::{OverlayConfig, OverlayProtocol, PortalnetConfig},
    types::ProtocolKind,
    U256,
};

/// History network layer on top of the overlay protocol. Encapsulates history network specific data and logic.
#[derive(Clone)]
pub struct HistoryNetwork {
    pub overlay: Arc<OverlayProtocol>,
}

impl HistoryNetwork {
    pub async fn new(
        discovery: Arc<RwLock<Discovery>>,
        portal_config: PortalnetConfig,
    ) -> Result<Self, String> {
        let config = OverlayConfig::default();
        let kbuckets = Arc::new(RwLock::new(KBucketsTable::new(
            discovery.read().await.local_enr().node_id().into(),
            config.bucket_pending_timeout,
            config.max_incoming_per_bucket,
            config.table_filter,
            config.bucket_filter,
        )));
        let data_radius = Arc::new(RwLock::new(portal_config.data_radius));

        let overlay = OverlayProtocol {
            discovery,
            data_radius,
            kbuckets,
        };

        let overlay = Arc::new(overlay);

        let proto = Self {
            overlay: Arc::clone(&overlay),
        };

        Ok(proto)
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
            debug!("Pinging {} on portal history network", enr);
            let ping_result = self
                .overlay
                .send_ping(U256::from(u64::MAX), enr, ProtocolKind::History)
                .await?;
            debug!("Portal history network Ping result: {:?}", ping_result);
        }
        Ok(())
    }
}
