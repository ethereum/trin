use std::sync::Arc;

use eth_trie::EthTrie;
use log::debug;
use rocksdb::DB;
use tokio::sync::RwLock;
use trin_core::locks::RwLoggingExt;
use trin_core::portalnet::{
    discovery::Discovery,
    overlay::{OverlayConfig, OverlayProtocol, SendPingError},
    types::{PortalnetConfig, ProtocolKind},
    U256,
};

use crate::trie::TrieDB;

/// State network layer on top of the overlay protocol. Encapsulates state network specific data and logic.
#[derive(Clone)]
pub struct StateNetwork {
    pub overlay: Arc<OverlayProtocol>,
    pub trie: Arc<EthTrie<TrieDB>>,
}

impl StateNetwork {
    pub async fn new(
        discovery: Arc<RwLock<Discovery>>,
        db: Arc<DB>,
        portal_config: PortalnetConfig,
    ) -> Self {
        let triedb = TrieDB::new(db.clone());
        let trie = EthTrie::new(Arc::new(triedb));

        let config = OverlayConfig::default();
        let overlay = OverlayProtocol::new(config, discovery, db, portal_config.data_radius).await;

        Self {
            overlay: Arc::new(overlay),
            trie: Arc::new(trie),
        }
    }

    /// Convenience call for testing, quick way to ping bootnodes
    pub async fn ping_bootnodes(&mut self) -> Result<(), String> {
        // Trigger bonding with bootnodes, at both the base layer and portal overlay.
        // The overlay ping via talkreq will trigger a session at the base layer, then
        // a session on the (overlay) portal network.
        let table_entries = {
            // use a nested scope so that the guard is quickly dropped
            let guard = self.overlay.discovery.read_with_warn().await;
            guard.discv5.table_entries_enr()
        };
        for enr in table_entries {
            debug!("Attempting bond with bootnode {}", enr);
            let ping_result = self
                .overlay
                .send_ping(U256::from(u64::MAX), enr.clone(), ProtocolKind::State, None)
                .await;

            match ping_result {
                Ok(_) => {
                    debug!("Successfully bonded with {}", enr);
                    continue;
                }
                Err(SendPingError::Timeout) => {
                    debug!("Timed out while bonding with {}", enr);
                    continue;
                }
                Err(SendPingError::Other(err)) => {
                    debug!("Unexpected error while bonding with {} => {:?}", enr, err);
                    return Err(err.to_string());
                }
            }
        }
        Ok(())
    }
}
