use std::time::Duration;

use anyhow::{anyhow, bail};
use discv5::enr::NodeId;
use ethportal_api::{
    generate_random_node_ids, jsonrpsee::http_client::HttpClient, types::network::Subnetwork,
    BeaconNetworkApiClient, Enr, HistoryNetworkApiClient, StateNetworkApiClient,
};
use futures::{future::JoinAll, StreamExt};
use itertools::Itertools;
use tokio::{
    sync::Semaphore,
    time::{Instant, Interval},
};
use tracing::{debug, error, info, warn};

use crate::{
    census::CensusError,
    cli::{BridgeConfig, ClientType},
};

use super::peers::Peers;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The result of the liveness check.
enum LivenessResult {
    /// We pinged the peer successfully
    Pass,
    /// We failed to ping peer
    Fail,
    /// Peer is already registered and not expired (we didn't try to ping the peer)
    AlreadyRegistered,
}

#[derive(Debug, Clone)]
/// The configuration for [Network] initialization. See [Network::init] for details.
pub(super) struct NetworkInitializationConfig {
    /// The number of requests to execute in parallel.
    concurrency: usize,
    /// Controls the number of recursive-find-nodes requests per "node discovery" iteration.
    ///
    /// The actual number of requests will be: `2^discovery_degree`.
    /// Value has to be between `0` (1 request) and `8` (256 requests), inclusively.
    discovery_degree: u32,
    /// Controls when to stop "node discovery" loop.
    stop_fraction_threshold: f64,
}

impl NetworkInitializationConfig {
    const DEFAULT_DISCOVERY_DEGREE: u32 = 4;
    const DEFAULT_STOP_FRACTION_THRESHOLD: f64 = 0.1;
}

impl Default for NetworkInitializationConfig {
    fn default() -> Self {
        Self {
            concurrency: 1 << Self::DEFAULT_DISCOVERY_DEGREE,
            discovery_degree: Self::DEFAULT_DISCOVERY_DEGREE,
            stop_fraction_threshold: Self::DEFAULT_STOP_FRACTION_THRESHOLD,
        }
    }
}

/// `Network` is responsible for maintaining a list of known peers in a subnetwork.
///
/// The [Network::init] should be used to initialize our view of the network, and [NetworkManager]
/// should be used in a background task to keep it up-to-date.
#[derive(Clone)]
pub(super) struct Network {
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

    pub fn create_manager(&self) -> NetworkManager {
        NetworkManager::new(self.clone())
    }

    // Look up all known interested enrs for a given content id
    pub fn get_interested_enrs(&self, content_id: &[u8; 32]) -> Result<Vec<Enr>, CensusError> {
        if self.peers.is_empty() {
            error!(
                subnetwork = %self.subnetwork,
                "No known peers, unable to look up interested enrs",
            );
            return Err(CensusError::NoPeers);
        }
        Ok(self
            .peers
            .get_interested_enrs(content_id, self.enr_offer_limit))
    }

    /// Returns whether `enr` represents eligible peer.
    ///
    /// Currently this only filters out peers based on client type (using `filter_client` field).
    fn is_eligible(&self, enr: &Enr) -> bool {
        self.filter_clients.is_empty() || !self.filter_clients.contains(&ClientType::from(enr))
    }

    /// Initializes the peers.
    ///
    /// Runs "node discovery" in a loop, and stops once number of newly discovered nodes is less
    /// than fraction of all peers, configured by `config.stop_fraction_threshold`.
    ///
    /// Each "node discovery" iteration will generate `2^config.discovery_degree` random Node Ids.
    /// Each Node Id will have unique `config.discovery_degree` most significant bits, in order to
    /// spread Node Ids across key space.
    pub async fn init(&mut self, config: &NetworkInitializationConfig) -> Result<(), CensusError> {
        info!(
            subnetwork = %self.subnetwork,
            filter_clients = ?self.filter_clients,
            "init: started",
        );

        let semaphore = Semaphore::new(config.concurrency);

        loop {
            // Generate random Node Ids
            let node_ids = generate_random_node_ids(config.discovery_degree);

            // Concurrent execution of recursive_find_nodes
            let results = node_ids
                .iter()
                .map(|node_id| async {
                    if let Ok(_permit) = semaphore.acquire().await {
                        self.recursive_find_nodes(*node_id).await
                    } else {
                        bail!("failed to acquire permit")
                    }
                })
                .collect::<JoinAll<_>>()
                .await;

            let enrs = results
                .into_iter()
                // Extract all ENRs
                .flat_map(|result| match result {
                    Ok(enrs) => enrs,
                    Err(err) => {
                        error!(
                            subnetwork = %self.subnetwork,
                            "init: RFN failed - err: {err}",
                        );
                        vec![]
                    }
                })
                // Group by NodeId
                .into_grouping_map_by(|enr| enr.node_id())
                // Select ENR with maximum sequence number
                .max_by_key(|_node_id, enr| enr.seq())
                .into_values()
                .collect_vec();

            // Concurrent execution of liveness check
            let new_peers = enrs
                .iter()
                .map(|enr| async {
                    if let Ok(_permit) = semaphore.acquire().await {
                        self.liveness_check(enr.clone()).await
                    } else {
                        error!(
                            subnetwork = %self.subnetwork,
                            "init: liveness check failed - permit",
                        );
                        LivenessResult::Fail
                    }
                })
                .collect::<JoinAll<_>>()
                .await
                .into_iter()
                .filter(|liveness_result| liveness_result == &LivenessResult::Pass)
                .count();

            let total_peers = self.peers.len();

            debug!(
                subnetwork = %self.subnetwork,
                "init: added {new_peers} / {total_peers} peers",
            );

            // Stop if number of new peers is less than a threshold fraction of all peers
            if (new_peers as f64) < (total_peers as f64) * config.stop_fraction_threshold {
                break;
            }
        }

        if self.peers.is_empty() {
            error!(
                subnetwork = %self.subnetwork,
                "init: failed - couldn't find any peers",
            );
            return Err(CensusError::FailedInitialization("No peers found"));
        }

        info!(
            subnetwork = %self.subnetwork,
            "init: finished - found {} peers",
            self.peers.len(),
        );
        Ok(())
    }

    /// Performs liveness check.
    ///
    /// Liveness check will pass if peer respond to a Ping request. It returns
    /// `LivenessResult::AlreadyRegistered` if peer is already registered and not expired.
    async fn liveness_check(&self, enr: Enr) -> LivenessResult {
        // if enr is already registered, check if delay map deadline has expired
        if let Some(deadline) = self.peers.deadline(&enr) {
            if Instant::now() < deadline {
                return LivenessResult::AlreadyRegistered;
            }
        }

        if self.ping(enr).await {
            LivenessResult::Pass
        } else {
            LivenessResult::Fail
        }
    }

    async fn ping(&self, enr: Enr) -> bool {
        if !self.is_eligible(&enr) {
            return false;
        }

        let future_response = match self.subnetwork {
            Subnetwork::History => HistoryNetworkApiClient::ping(&self.client, enr.clone()),
            Subnetwork::State => StateNetworkApiClient::ping(&self.client, enr.clone()),
            Subnetwork::Beacon => BeaconNetworkApiClient::ping(&self.client, enr.clone()),
            _ => unreachable!("Unsupported subnetwork: {}", self.subnetwork),
        };
        let response = future_response.await.map_err(|e| anyhow!(e));
        self.peers.process_ping_response(enr, response)
    }

    async fn recursive_find_nodes(&self, node_id: NodeId) -> anyhow::Result<Vec<Enr>> {
        let enrs = match self.subnetwork {
            Subnetwork::History => {
                HistoryNetworkApiClient::recursive_find_nodes(&self.client, node_id).await?
            }
            Subnetwork::State => {
                StateNetworkApiClient::recursive_find_nodes(&self.client, node_id).await?
            }
            Subnetwork::Beacon => {
                BeaconNetworkApiClient::recursive_find_nodes(&self.client, node_id).await?
            }
            _ => unreachable!("Unsupported subnetwork: {}", self.subnetwork),
        };
        Ok(enrs
            .into_iter()
            .filter(|enr| self.is_eligible(enr))
            .collect())
    }
}

/// The action to execute in order to keep up-to-date view of the subnetwork.
pub enum NetworkAction {
    /// Peers re-initialization (required when no peers are available)
    ReInitialization,
    /// Run peer discovery (RFN for random Node Id)
    PeerDiscovery,
    /// Check the liveness of the discovered peer
    LivenessCheck(Enr),
}

/// `NetworkManager` is responsible for keeping `Network`'s view of the network up to date.
///
/// It should be used in a background task.
pub(super) struct NetworkManager {
    network: Network,
    peer_discovery_interval: Interval,
}

impl NetworkManager {
    /// Configures how frequently to run recursive-find-nodes for a random NodeId in order to keep
    /// discovering new nodes.
    const PEER_DISCOVERY_INTERVAL: Duration = Duration::from_secs(60);

    pub fn new(network: Network) -> Self {
        Self {
            network,
            peer_discovery_interval: tokio::time::interval(Self::PEER_DISCOVERY_INTERVAL),
        }
    }

    /// Returns next action that should be executed.
    pub async fn next_action(&mut self) -> NetworkAction {
        loop {
            tokio::select! {
                _ = self.peer_discovery_interval.tick() => {
                    return NetworkAction::PeerDiscovery;
                }
                peer = self.network.peers.next() => {
                    match peer {
                        Some(Ok(enr)) => {
                            return NetworkAction::LivenessCheck(enr);
                        }
                        Some(Err(err)) => {
                            error!(
                                subnetwork = %self.network.subnetwork,
                                "next-action: error getting peer - err: {err}",
                            );
                        }
                        None => {
                            warn!(
                                subnetwork = %self.network.subnetwork,
                                "next-action: no pending peers - re-initializing",
                            );
                            return NetworkAction::ReInitialization;
                        }
                    }
                }
            }
        }
    }

    pub async fn execute_action(&mut self, action: NetworkAction) {
        match action {
            NetworkAction::ReInitialization => {
                if let Err(err) = self
                    .network
                    .init(&NetworkInitializationConfig {
                        concurrency: 1,
                        ..Default::default()
                    })
                    .await
                {
                    error!(
                        subnetwork = %self.network.subnetwork,
                        "execute-action: error re-initializing - err: {err}",
                    );
                }
            }
            NetworkAction::PeerDiscovery => self.peer_discovery().await,
            NetworkAction::LivenessCheck(enr) => {
                if self.network.liveness_check(enr).await == LivenessResult::AlreadyRegistered {
                    warn!(
                        subnetwork = %self.network.subnetwork,
                        "execute-action: liveness check on already registered peer",
                    );
                }
            }
        }
    }

    async fn peer_discovery(&mut self) {
        let node_id = NodeId::random();
        let enrs = match self.network.recursive_find_nodes(node_id).await {
            Ok(enrs) => enrs,
            Err(err) => {
                error!(
                    subnetwork = %self.network.subnetwork,
                    "peer-discovery: RFN failed - err: {err}",
                );
                return;
            }
        };

        let mut new_peers = 0;
        for enr in enrs {
            if self.network.liveness_check(enr).await == LivenessResult::Pass {
                new_peers += 1;
            }
        }

        let total_peers = self.network.peers.len();
        info!(
            subnetwork = %self.network.subnetwork,
            "peer-discovery: finished - discovered {new_peers} / {total_peers} peers",
        );
    }
}
