use log::debug;
use rocksdb::DB;
use std::sync::Arc;
use trin_core::portalnet::{
    discovery::Discovery,
    overlay::{OverlayConfig, OverlayProtocol, OverlayRequestError},
    types::{PortalnetConfig, ProtocolId},
};

/// History network layer on top of the overlay protocol. Encapsulates history network specific data and logic.
#[derive(Clone)]
pub struct HistoryNetwork {
    pub overlay: Arc<OverlayProtocol>,
}

impl HistoryNetwork {
    pub async fn new(
        discovery: Arc<Discovery>,
        db: Arc<DB>,
        portal_config: PortalnetConfig,
    ) -> Self {
        let config = OverlayConfig::default();
        let overlay = OverlayProtocol::new(
            config,
            discovery,
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
    pub async fn ping_bootnodes(&mut self) -> Result<(), String> {
        // Trigger bonding with bootnodes, at both the base layer and portal overlay.
        // The overlay ping via talkreq will trigger a session at the base layer, then
        // a session on the (overlay) portal network.
        for enr in self.overlay.discovery.discv5.table_entries_enr() {
            debug!("Pinging {} on portal history network", enr);
            let ping_result = self.overlay.send_ping(enr.clone(), None).await;

            match ping_result {
                Ok(_) => {
                    debug!("Successfully bonded with {}", enr);
                    continue;
                }
                Err(OverlayRequestError::ChannelFailure(error)) => {
                    debug!("Channel failure sending ping: {}", error);
                    continue;
                }
                Err(OverlayRequestError::Timeout) => {
                    debug!("Timed out while bonding with {}", enr);
                    continue;
                }
                Err(OverlayRequestError::EmptyResponse) => {
                    debug!("Empty response to ping from: {}", enr);
                    continue;
                }
                Err(OverlayRequestError::InvalidRequest) => {
                    debug!("Sent invalid ping response to {}", enr);
                    continue;
                }
                Err(OverlayRequestError::InvalidResponse) => {
                    debug!("Invalid ping response from: {}", enr);
                    continue;
                }
                Err(OverlayRequestError::DecodeError) => {
                    debug!("Error decoding ping response from: {}", enr);
                    continue;
                }
                Err(OverlayRequestError::Discv5Error(error)) => {
                    debug!("Unexpected error while bonding with {} => {:?}", enr, error);
                    return Err(error.to_string());
                }
            }
        }
        Ok(())
    }
}
