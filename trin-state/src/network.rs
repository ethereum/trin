use std::sync::Arc;

use discv5::enr::NodeId;
use eth_trie::EthTrie;
use parking_lot::RwLock as PLRwLock;
use tokio::sync::{mpsc::UnboundedSender, RwLock};

use trin_core::{
    portalnet::{
        discovery::Discovery,
        overlay::{OverlayConfig, OverlayProtocol},
        storage::{PortalStorage, PortalStorageConfig},
        types::{
            content_key::StateContentKey,
            distance::XorMetric,
            messages::{PortalnetConfig, ProtocolId},
        },
    },
    types::header_oracle::HeaderOracle,
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
        header_oracle: Arc<RwLock<HeaderOracle>>,
    ) -> Self {
        // todo: revisit triedb location
        let db = PortalStorage::setup_rocksdb(NodeId::random()).unwrap();
        let triedb = TrieDB::new(Arc::new(db));
        let trie = EthTrie::new(Arc::new(triedb));

        let storage = Arc::new(PLRwLock::new(PortalStorage::new(storage_config).unwrap()));
        let validator = Arc::new(StateValidator { header_oracle });
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
}
