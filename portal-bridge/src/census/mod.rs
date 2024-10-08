use std::collections::HashSet;

use ethportal_api::{jsonrpsee::http_client::HttpClient, types::network::Subnetwork, Enr};
use thiserror::Error;
use tokio::task::JoinHandle;
use tracing::{error, info, Instrument};

use crate::cli::BridgeConfig;
use network::Network;

mod network;
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
pub struct Census {
    history: Network,
    state: Network,
    beacon: Network,
    initialized: bool,
}

impl Census {
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
        if self.initialized {
            return Err(CensusError::AlreadyInitialized);
        }
        self.initialized = true;

        let subnetworks = HashSet::from_iter(subnetworks);
        if subnetworks.is_empty() {
            return Err(CensusError::FailedInitialization("No subnetwork"));
        }
        for subnetwork in &subnetworks {
            info!("Initializing {subnetwork} subnetwork");
            match subnetwork {
                Subnetwork::History => self.history.init().await?,
                Subnetwork::State => self.state.init().await?,
                Subnetwork::Beacon => self.beacon.init().await?,
                _ => return Err(CensusError::UnsupportedSubnetwork(*subnetwork)),
            }
        }

        Ok(self.start_background_service(subnetworks))
    }

    /// Starts background service that is responsible for keeping view of the network up to date.
    ///
    /// Selects available tasks and runs them. Tasks are provided by enabled subnetworks.
    fn start_background_service(&self, subnetworks: HashSet<Subnetwork>) -> JoinHandle<()> {
        let mut history_network = self.history.clone();
        let mut state_network = self.state.clone();
        let mut beacon_network = self.beacon.clone();
        let service = async move {
            loop {
                tokio::select! {
                    peer = history_network.peer_to_process(), if subnetworks.contains(&Subnetwork::History) => {
                        history_network.process_peer(peer).await;
                    }
                    peer = state_network.peer_to_process(), if subnetworks.contains(&Subnetwork::State) => {
                        state_network.process_peer(peer).await;
                    }
                    peer = beacon_network.peer_to_process(), if subnetworks.contains(&Subnetwork::Beacon) => {
                        beacon_network.process_peer(peer).await;
                    }
                }
            }
        };
        tokio::spawn(service.instrument(tracing::trace_span!("census").or_current()))
    }
}
