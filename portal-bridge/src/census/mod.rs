use std::collections::HashSet;

use ethportal_api::{jsonrpsee::http_client::HttpClient, types::network::Subnetwork, Enr};
use thiserror::Error;
use tokio::task::JoinHandle;
use tracing::{error, info, Instrument};

use crate::cli::BridgeConfig;
use network::{Network, NetworkAction, NetworkInitializationConfig, NetworkManager};

mod network;
mod peer;
mod peers;

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

/// The maximum number of enrs to return in a response,
/// limiting the number of OFFER requests spawned by the bridge
/// for each piece of content
pub const ENR_OFFER_LIMIT: usize = 4;

/// The census is responsible for maintaining a list of known peers in the network,
/// checking their liveness, updating their data radius, iterating through their
/// rfn to find new peers, and providing interested enrs for a given content id.
#[derive(Clone)]
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

    /// Returns ENRs interested in provided content id.
    pub fn get_interested_enrs(
        &self,
        subnetwork: Subnetwork,
        content_id: &[u8; 32],
    ) -> Result<Vec<Enr>, CensusError> {
        match subnetwork {
            Subnetwork::History => self.history.get_interested_enrs(content_id),
            Subnetwork::State => self.state.get_interested_enrs(content_id),
            Subnetwork::Beacon => self.beacon.get_interested_enrs(content_id),
            _ => Err(CensusError::UnsupportedSubnetwork(subnetwork)),
        }
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
