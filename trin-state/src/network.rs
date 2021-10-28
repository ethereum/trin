use std::sync::Arc;

use eth_trie::{EthTrie, Trie, TrieError};
use keccak_hash::keccak;
use log::debug;
use rocksdb::DB;
use tokio::sync::RwLock;
use trin_core::locks::RwLoggingExt;
use trin_core::portalnet::{
    discovery::Discovery,
    overlay::{OverlayConfig, OverlayProtocol, OverlayRequestError},
    types::{FoundContent, PortalnetConfig, ProtocolId},
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

    pub async fn get_encoded_account(&self, address: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let hashed_addr = keccak(address);
        self._get_encoded_account(hashed_addr.as_bytes()).await
    }

    pub async fn _get_encoded_account(&self, hashed_addr: &[u8]) -> Result<Option<Vec<u8>>, String> {
        match self.trie.get(hashed_addr) {
            Ok(value) => Ok(value),
            Err(TrieError::MissingTrieNode { node_hash, .. }) => {
                let hash_bytes = node_hash.as_bytes();
                let node_body = match self.find_content(hash_bytes).await {
                    Ok(received) => received,
                    _ => { return _; },
                };
                self.trie.insert(hash_bytes, node_body);
                // TODO - might need to trie.commit here, or change eth-trie to check the pending
                //  writes during a read.

                // Now that the missing trie node is inserted, we can re-attempt the trie read
                self._get_encoded_account(hashed_addr).await
            },
            Err(any) => Err(any.to_string()),
        }
    }

    async fn find_content(&self, content_key: &[u8]) -> Result<Vec<u8>, String> {
        let ENRs = self.overlay.find_nodes_close_to_content(content_key).await;
        for enr in ENRs {
            let content = self.overlay.send_find_content(content_key, enr, ProtocolId::State).await;

            match content {
                // TODO grab ENRs from response, for more peer lookup opportunities
                Ok(FoundContent { enrs, payload }) => { return Ok(payload); },
                // TODO log errors as debug
                _ => { continue; },
            }
        }
        Err(format!("Exhausted peer set looking for content {:?}", content_key))
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
                .send_ping(U256::from(u64::MAX), enr.clone(), ProtocolId::State, None)
                .await;

            match ping_result {
                Ok(_) => {
                    debug!("Successfully bonded with {}", enr);
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
                Err(OverlayRequestError::InvalidResponse) => {
                    debug!("Invalid ping response from: {}", enr);
                    continue;
                }
                Err(OverlayRequestError::DecodeError) => {
                    debug!("Error decoding ping response from: {}", enr);
                    continue;
                }
                Err(OverlayRequestError::Other(err)) => {
                    debug!("Unexpected error while bonding with {} => {:?}", enr, err);
                    return Err(err.to_string());
                }
            }
        }
        Ok(())
    }
}
