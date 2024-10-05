use anyhow::anyhow;
use discv5::enr::NodeId;
use ethportal_api::{
    generate_random_remote_enr, jsonrpsee::http_client::HttpClient, types::network::Subnetwork,
    BeaconNetworkApiClient, Enr, HistoryNetworkApiClient, StateNetworkApiClient,
};
use futures::StreamExt;
use tokio::time::Instant;
use tracing::{error, info, warn};

use crate::{
    census::CensusError,
    cli::{BridgeConfig, ClientType},
};

use super::peers::Peers;

/// The network struct is responsible for maintaining a list of known peers
/// in the given subnetwork.
#[derive(Clone)]
pub struct Network {
    peers: Peers,
    client: HttpClient,
    subnetwork: Subnetwork,
    filter_clients: Vec<ClientType>,
    enr_offer_limit: usize,
}

impl Network {
    pub fn new(client: HttpClient, subnetwork: Subnetwork, bridge_config: &BridgeConfig) -> Self {
        if !matches!(
            subnetwork,
            Subnetwork::History | Subnetwork::Beacon | Subnetwork::State
        ) {
            panic!("Unsupported subnetwork: {subnetwork}");
        }

        Self {
            peers: Peers::new(),
            client,
            subnetwork,
            filter_clients: bridge_config.filter_clients.to_vec(),
            enr_offer_limit: bridge_config.enr_offer_limit,
        }
    }

    // Look up all known interested enrs for a given content id
    pub fn get_interested_enrs(&self, content_id: &[u8; 32]) -> Result<Vec<Enr>, CensusError> {
        if self.peers.is_empty() {
            error!(
                "No known peers in {} census, unable to offer.",
                self.subnetwork
            );
            return Err(CensusError::NoPeers);
        }
        Ok(self
            .peers
            .get_interested_enrs(content_id, self.enr_offer_limit))
    }

    /// Initialize the peers.
    ///
    /// We initialize a network with a random rfn lookup to get an initial view of the network
    /// and then iterate through the rfn of each peer to find new peers. Since this initialization
    /// blocks the bridge's gossip feature, there is a tradeoff between the time taken to initialize
    /// the census and the time taken to start gossiping. In the future, we might consider updating
    /// the initialization process to be considered complete after it has found ~100% of the network
    /// peers. However, since the census continues to iterate through the peers after
    /// initialization, the initialization is just to reach a critical mass of peers so that gossip
    /// can begin.
    pub async fn init(&self) -> Result<(), CensusError> {
        match self.filter_clients.is_empty() {
            true => info!("Initializing {} network census", self.subnetwork),
            false => info!(
                "Initializing {} network census with filtered clients: {:?}",
                self.subnetwork, self.filter_clients
            ),
        }
        let (_, random_enr) = generate_random_remote_enr();
        let Ok(initial_enrs) = self.recursive_find_nodes(random_enr.node_id()).await else {
            error!(
                "Failed to initialize {} census, RFN failed",
                self.subnetwork
            );
            return Err(CensusError::FailedInitialization);
        };

        // if this initialization is too slow, we can consider
        // refactoring the peers structure so that it can be
        // run in parallel
        for enr in initial_enrs {
            self.process_enr(enr).await;
        }
        if self.peers.is_empty() {
            error!(
                "Failed to initialize {} census, couldn't find any peers.",
                self.subnetwork
            );
            return Err(CensusError::FailedInitialization);
        }
        info!(
            "Initialized {} census: found peers: {}",
            self.subnetwork,
            self.peers.len()
        );
        Ok(())
    }

    /// Returns next peer to process.
    pub async fn peer_to_process(&mut self) -> Option<Result<Enr, String>> {
        self.peers.next().await
    }

    /// Processes the peer.
    ///
    /// If no peer is found, reinitilizes the network.
    pub async fn process_peer(&self, peer: Option<Result<Enr, String>>) {
        let subnetwork = &self.subnetwork;
        match peer {
            Some(Ok(enr)) => {
                self.process_enr(enr).await;
            }
            Some(Err(err)) => {
                error!("Error getting peer to process for {subnetwork} subnetwork: {err}");
            }
            None => {
                warn!("No peers pending! Re-initializing {subnetwork} subnetwork");
                if let Err(err) = self.init().await {
                    error!("Error initializing {subnetwork} subnetwork: {err}");
                }
            }
        }
    }

    /// Only processes an enr (iterating through its rfn) if the enr's
    /// liveness delay has expired
    async fn process_enr(&self, enr: Enr) {
        // ping for liveliness check
        if !self.liveness_check(enr.clone()).await {
            return;
        }
        // iterate peers routing table via rfn over various distances
        for distance in 245..257 {
            let Ok(result) = self.find_nodes(enr.clone(), vec![distance]).await else {
                warn!("Find nodes request failed for enr: {}", enr);
                continue;
            };
            for found_enr in result {
                self.liveness_check(found_enr).await;
            }
        }
        info!(
            "Updated {} census. Available peers: {}",
            self.subnetwork,
            self.peers.len(),
        );
    }

    /// Performs liveness check.
    ///
    /// Liveness check will pass if
    /// If they are registered but expired, we shouldn't perform liveness checked now as it will be
    /// done when they are polled as expired (soon).
    pub async fn liveness_check(&self, enr: Enr) -> bool {
        // skip if client type is filtered
        let client_type = ClientType::from(&enr);
        if self.filter_clients.contains(&client_type) {
            return false;
        }

        // if enr is already registered, check if delay map deadline has expired
        if let Some(deadline) = self.peers.deadline(&enr) {
            if Instant::now() < deadline {
                return false;
            }
        }

        self.ping(enr).await
    }

    async fn ping(&self, enr: Enr) -> bool {
        let future_response = match self.subnetwork {
            Subnetwork::History => HistoryNetworkApiClient::ping(&self.client, enr.clone()),
            Subnetwork::State => StateNetworkApiClient::ping(&self.client, enr.clone()),
            Subnetwork::Beacon => BeaconNetworkApiClient::ping(&self.client, enr.clone()),
            _ => unreachable!("Unsupported subnetwork: {}", self.subnetwork),
        };
        let response = future_response.await.map_err(|e| anyhow!(e));
        self.peers.process_ping_response(enr, response)
    }

    async fn find_nodes(&self, enr: Enr, distances: Vec<u16>) -> anyhow::Result<Vec<Enr>> {
        let result = match self.subnetwork {
            Subnetwork::History => {
                HistoryNetworkApiClient::find_nodes(&self.client, enr, distances).await
            }
            Subnetwork::State => {
                StateNetworkApiClient::find_nodes(&self.client, enr, distances).await
            }
            Subnetwork::Beacon => {
                BeaconNetworkApiClient::find_nodes(&self.client, enr, distances).await
            }
            _ => unreachable!("Unsupported subnetwork: {}", self.subnetwork),
        };
        result.map_err(|e| anyhow!(e))
    }

    async fn recursive_find_nodes(&self, node_id: NodeId) -> anyhow::Result<Vec<Enr>> {
        let result = match self.subnetwork {
            Subnetwork::History => {
                HistoryNetworkApiClient::recursive_find_nodes(&self.client, node_id).await
            }
            Subnetwork::State => {
                StateNetworkApiClient::recursive_find_nodes(&self.client, node_id).await
            }
            Subnetwork::Beacon => {
                BeaconNetworkApiClient::recursive_find_nodes(&self.client, node_id).await
            }
            _ => unreachable!("Unsupported subnetwork: {}", self.subnetwork),
        };
        result.map_err(|e| anyhow!(e))
    }
}
