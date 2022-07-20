use std::sync::Arc;

use discv5::enr::NodeId;
use eth_trie::EthTrie;
use log::{debug, error};
use parking_lot::RwLock;
use tokio::sync::mpsc::UnboundedSender;
use trin_core::{
    portalnet::{
        discovery::Discovery,
        overlay::{OverlayConfig, OverlayProtocol},
        storage::{PortalStorage, PortalStorageConfig},
        types::{
            content_key::StateContentKey,
            messages::{PortalnetConfig, ProtocolId},
            metric::XorMetric,
        },
    },
    types::validation::HeaderOracle,
    utp::stream::UtpListenerRequest,
};

use crate::{trie::TrieDB, validation::StateValidator};

/// State network layer on top of the overlay protocol. Encapsulates state network specific data and logic.
#[derive(Clone)]
pub struct StateNetwork {
    pub overlay: Arc<OverlayProtocol<StateContentKey, XorMetric, StateValidator>>,
    pub trie: Arc<EthTrie<TrieDB>>,
}

impl StateNetwork {
    pub async fn new(
        discovery: Arc<Discovery>,
        utp_listener_tx: UnboundedSender<UtpListenerRequest>,
        storage_config: PortalStorageConfig,
        portal_config: PortalnetConfig,
    ) -> Self {
        // todo: revisit triedb location
        let db = PortalStorage::setup_rocksdb(NodeId::random()).unwrap();
        let triedb = TrieDB::new(Arc::new(db));
        let trie = EthTrie::new(Arc::new(triedb));

        let storage = Arc::new(RwLock::new(PortalStorage::new(storage_config).unwrap()));
        let validator = Arc::new(StateValidator {
            header_oracle: HeaderOracle::default(),
        });
        let config = OverlayConfig {
            bootnode_enrs: portal_config.bootnode_enrs.clone(),
            enable_metrics: portal_config.enable_metrics,
            ..Default::default()
        };
        let overlay = OverlayProtocol::new(
            config,
            discovery,
            utp_listener_tx,
            storage,
            portal_config.data_radius,
            ProtocolId::State,
            validator,
        )
        .await;

        Self {
            overlay: Arc::new(overlay),
            trie: Arc::new(trie),
        }
    }

    /// Convenience call for testing, quick way to ping bootnodes
    pub async fn ping_bootnodes(&self) -> anyhow::Result<()> {
        // Trigger bonding with bootnodes, at both the base layer and portal overlay.
        // The overlay ping via talkreq will trigger a session at the base layer, then
        // a session on the (overlay) portal network.
        for enr in self.overlay.discovery.discv5.table_entries_enr() {
            debug!("Attempting bond with bootnode {}", enr);
            let ping_result = self.overlay.send_ping(enr.clone()).await;

            match ping_result {
                Ok(_) => {
                    debug!("Successfully bonded with {}", enr);
                    continue;
                }
                Err(err) => {
                    error!("{err} while pinging bootnode: {enr:?}");
                }
            }
        }
        Ok(())
    }
}
