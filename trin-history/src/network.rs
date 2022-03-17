use anyhow::anyhow;
use log::debug;
use std::sync::Arc;

use tokio::sync::RwLock;

use trin_core::portalnet::{
    discovery::Discovery,
    overlay::{OverlayConfig, OverlayProtocol, OverlayRequestError},
    storage::{PortalStorage, PortalStorageConfig},
    types::messages::{PortalnetConfig, ProtocolId},
};
use trin_core::utp::stream::UtpListener;

use super::content_key::HistoryContentKey;

/// History network layer on top of the overlay protocol. Encapsulates history network specific data and logic.
#[derive(Clone)]
pub struct HistoryNetwork {
    pub overlay: Arc<OverlayProtocol<HistoryContentKey>>,
}

impl HistoryNetwork {
    pub async fn new(
        discovery: Arc<Discovery>,
        utp_listener: Arc<RwLock<UtpListener>>,
        storage_config: PortalStorageConfig,
        portal_config: PortalnetConfig,
    ) -> Self {
        let config = OverlayConfig {
            bootnode_enrs: portal_config.bootnode_enrs.clone(),
            enable_metrics: portal_config.enable_metrics,
            ..Default::default()
        };
        let storage = Arc::new(PortalStorage::new(storage_config).unwrap());
        let overlay = OverlayProtocol::new(
            config,
            discovery,
            utp_listener,
            storage,
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
                Err(OverlayRequestError::InvalidRequest(_)) => {
                    debug!("Sent invalid ping request to {}", enr);
                    continue;
                }
                Err(OverlayRequestError::InvalidResponse) => {
                    debug!("Invalid ping response from: {}", enr);
                    continue;
                }
                Err(OverlayRequestError::Failure(_)) => {
                    debug!("Failure to serve ping response from: {}", enr);
                    continue;
                }
                Err(OverlayRequestError::DecodeError) => {
                    debug!("Error decoding ping response from: {}", enr);
                    continue;
                }
                Err(OverlayRequestError::AcceptError(error)) => {
                    debug!("Error building Accept message: {:?}", error);
                }
                Err(OverlayRequestError::Discv5Error(error)) => {
                    debug!("Unexpected error while bonding with {} => {:?}", enr, error);
                    return Err(anyhow!(error.to_string()));
                }
                _ => {
                    let msg = format!("Unexpected error while bonding with {enr}");
                    debug!("{msg}");
                    return Err(anyhow!(msg));
                }
            }
        }
        Ok(())
    }
}
