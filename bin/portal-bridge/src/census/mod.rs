use std::{collections::HashSet, time::Duration};

use discv5::enr::NodeId;
use ethportal_api::{
    jsonrpsee::http_client::HttpClient,
    types::{network::Subnetwork, portal_wire::OfferTrace},
};
use network::{Network, NetworkAction, NetworkInitializationConfig, NetworkManager};
use peer::PeerInfo;
use thiserror::Error;
use tokio::task::JoinHandle;
use tracing::{error, info, Instrument};

use crate::cli::BridgeConfig;

pub mod client_type;
mod network;
pub(crate) mod peer;
mod peers;
mod scoring;

/// The error that occured in [Census].
#[derive(Error, Debug)]
pub enum CensusError {
    #[error("No peers found in Census")]
    NoPeers,
    #[error("Failed to initialize Census: {0}")]
    FailedInitialization(&'static str),
    #[error("Subnetwork {0} is not supported")]
    UnsupportedSubnetwork(Subnetwork),
    #[error("Census already initialized")]
    AlreadyInitialized,
}

/// The census is responsible for maintaining a list of known peers in the network,
/// checking their liveness, updating their data radius, iterating through their
/// rfn to find new peers, and providing interested enrs for a given content id.
#[derive(Clone, Debug)]
pub struct Census {
    history: Network,
    state: Network,
    beacon: Network,
    initialized: bool,
}

impl Census {
    const SUPPORTED_SUBNETWORKS: [Subnetwork; 3] =
        [Subnetwork::Beacon, Subnetwork::History, Subnetwork::State];

    pub fn new(client: HttpClient, bridge_config: &BridgeConfig) -> Self {
        Self {
            history: Network::new(client.clone(), Subnetwork::History, bridge_config),
            state: Network::new(client.clone(), Subnetwork::State, bridge_config),
            beacon: Network::new(client.clone(), Subnetwork::Beacon, bridge_config),
            initialized: false,
        }
    }

    /// Selects peers to receive content.
    pub fn select_peers(
        &self,
        subnetwork: Subnetwork,
        content_id: &[u8; 32],
    ) -> Result<Vec<PeerInfo>, CensusError> {
        match subnetwork {
            Subnetwork::History => self.history.select_peers(content_id),
            Subnetwork::State => self.state.select_peers(content_id),
            Subnetwork::Beacon => self.beacon.select_peers(content_id),
            _ => Err(CensusError::UnsupportedSubnetwork(subnetwork)),
        }
    }

    pub fn record_offer_result(
        &self,
        subnetwork: Subnetwork,
        node_id: NodeId,
        content_value_size: usize,
        duration: Duration,
        offer_trace: &OfferTrace,
    ) {
        let network = match subnetwork {
            Subnetwork::History => &self.history,
            Subnetwork::State => &self.state,
            Subnetwork::Beacon => &self.beacon,
            _ => {
                error!("record_offer_result: subnetwork {subnetwork} is not supported");
                return;
            }
        };
        network.record_offer_result(node_id, content_value_size, duration, offer_trace);
    }

    /// Initialize subnetworks and starts background service that will keep our view of the network
    /// up to date.
    ///
    /// Returns JoinHandle of the background service.
    pub async fn init(
        &mut self,
        subnetworks: impl IntoIterator<Item = Subnetwork>,
    ) -> Result<JoinHandle<()>, CensusError> {
        info!("Initializing census");

        if self.initialized {
            return Err(CensusError::AlreadyInitialized);
        }
        self.initialized = true;

        let subnetworks = HashSet::<Subnetwork>::from_iter(subnetworks);
        if subnetworks.is_empty() {
            return Err(CensusError::FailedInitialization("No subnetwork"));
        }
        for subnetwork in &subnetworks {
            if !Self::SUPPORTED_SUBNETWORKS.contains(subnetwork) {
                return Err(CensusError::UnsupportedSubnetwork(*subnetwork));
            }
        }

        let initialization_config = NetworkInitializationConfig::default();

        let mut beacon_manager = if subnetworks.contains(&Subnetwork::Beacon) {
            self.beacon.init(&initialization_config).await?;
            Some(self.beacon.create_manager())
        } else {
            None
        };
        let mut history_manager = if subnetworks.contains(&Subnetwork::History) {
            self.history.init(&initialization_config).await?;
            Some(self.history.create_manager())
        } else {
            None
        };
        let mut state_manager = if subnetworks.contains(&Subnetwork::State) {
            self.state.init(&initialization_config).await?;
            Some(self.state.create_manager())
        } else {
            None
        };

        let service = async move {
            loop {
                tokio::select! {
                    Some(action) = next_action(&mut beacon_manager) => {
                        if let Some(manager) = &mut beacon_manager {
                            manager.execute_action(action).await;
                        }
                    }
                    Some(action) = next_action(&mut history_manager) => {
                        if let Some(manager) = &mut history_manager {
                            manager.execute_action(action).await;
                        }
                    }
                    Some(action) = next_action(&mut state_manager) => {
                        if let Some(manager) = &mut state_manager {
                            manager.execute_action(action).await;
                        }
                    }
                }
            }
        };
        Ok(tokio::spawn(
            service.instrument(tracing::trace_span!("census").or_current()),
        ))
    }
}

async fn next_action(manager: &mut Option<NetworkManager>) -> Option<NetworkAction> {
    match manager {
        Some(manager) => Some(manager.next_action().await),
        None => None,
    }
}
