use std::sync::Arc;

use eth_trie::EthTrie;
use parking_lot::RwLock as PLRwLock;
use tokio::sync::RwLock;

use ethportal_api::types::distance::XorMetric;
use ethportal_api::types::enr::Enr;
use ethportal_api::types::portal_wire::ProtocolId;
use ethportal_api::StateContentKey;
use portalnet::{
    config::PortalnetConfig,
    discovery::Discovery,
    overlay::{OverlayConfig, OverlayProtocol},
    storage::{PortalStorage, PortalStorageConfig},
    utp_controller::UtpController,
};
use trin_validation::oracle::HeaderOracle;

use crate::{trie::TrieDB, validation::StateValidator};

/// State network layer on top of the overlay protocol. Encapsulates state network specific data and logic.
#[derive(Clone)]
pub struct StateNetwork {
    pub overlay: Arc<OverlayProtocol<StateContentKey, XorMetric, StateValidator, PortalStorage>>,
    pub trie: Arc<EthTrie<TrieDB>>,
}

impl StateNetwork {
    pub async fn new(
        discovery: Arc<Discovery>,
        utp_controller: Arc<UtpController>,
        storage_config: PortalStorageConfig,
        portal_config: PortalnetConfig,
        header_oracle: Arc<RwLock<HeaderOracle>>,
    ) -> anyhow::Result<Self> {
        let db = PortalStorage::setup_triedb(&storage_config.node_data_dir)?;
        let triedb = TrieDB::new(Arc::new(db));
        let trie = EthTrie::new(Arc::new(triedb));
        let storage = Arc::new(PLRwLock::new(PortalStorage::new(
            storage_config,
            ProtocolId::State,
        )?));
        let validator = Arc::new(StateValidator { header_oracle });
        let bootnode_enrs: Vec<Enr> = portal_config.bootnodes.into();
        let config = OverlayConfig {
            bootnode_enrs,
            ..Default::default()
        };
        let overlay = OverlayProtocol::new(
            config,
            discovery,
            utp_controller,
            storage,
            ProtocolId::State,
            validator,
        )
        .await;

        Ok(Self {
            overlay: Arc::new(overlay),
            trie: Arc::new(trie),
        })
    }
}
