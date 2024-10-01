use alloy_primitives::U256;
use anyhow::{anyhow, bail};
use delay_map::HashMapDelay;
use discv5::enr::NodeId;
use ethportal_api::{
    generate_random_remote_enr,
    jsonrpsee::http_client::HttpClient,
    types::{
        distance::{Distance, Metric, XorMetric},
        network::Subnetwork,
        portal::PongInfo,
    },
    BeaconNetworkApiClient, Enr, HistoryNetworkApiClient, StateNetworkApiClient,
};
use rand::seq::IteratorRandom;
use tokio::time::{Duration, Instant};
use tracing::{error, info, warn};

use crate::{
    census::CensusError,
    cli::{BridgeConfig, ClientType},
};

/// Ping delay for liveness check of peers in census
/// One hour was chosen after 2mins was too slow, and can be adjusted
/// in the future based on performance
const LIVENESS_CHECK_DELAY: Duration = Duration::from_secs(3600);

/// The network struct is responsible for maintaining a list of known peers
/// in the given subnetwork.
pub struct Network {
    pub peers: HashMapDelay<[u8; 32], (Enr, Distance)>,
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
            peers: HashMapDelay::new(LIVENESS_CHECK_DELAY),
            client,
            subnetwork,
            filter_clients: bridge_config.filter_clients.to_vec(),
            enr_offer_limit: bridge_config.enr_offer_limit,
        }
    }

    // We initialize a network with a random rfn lookup to get an initial view of the network
    // and then iterate through the rfn of each peer to find new peers. Since this initialization
    // blocks the bridge's gossip feature, there is a tradeoff between the time taken to initialize
    // the census and the time taken to start gossiping. In the future, we might consider updating
    // the initialization process to be considered complete after it has found ~100% of the network
    // peers. However, since the census continues to iterate through the peers after initialization,
    // the initialization is just to reach a critical mass of peers so that gossip can begin.
    pub async fn init(&mut self) {
        match self.filter_clients.is_empty() {
            true => info!("Initializing {} network census", self.subnetwork),
            false => info!(
                "Initializing {} network census with filtered clients: {:?}",
                self.subnetwork, self.filter_clients
            ),
        }
        let (_, random_enr) = generate_random_remote_enr();
        let Ok(initial_enrs) = self
            .recursive_find_nodes(&self.client, random_enr.node_id())
            .await
        else {
            panic!("Failed to initialize network census");
        };

        // if this initialization is too slow, we can consider
        // refactoring the peers structure so that it can be
        // run in parallel
        for enr in initial_enrs {
            self.process_enr(enr).await;
        }
        if self.peers.is_empty() {
            panic!(
                "Failed to initialize {} census, couldn't find any peers.",
                self.subnetwork
            );
        }
        info!(
            "Initialized {} census: found peers: {}",
            self.subnetwork,
            self.peers.len()
        );
    }

    /// Only processes an enr (iterating through its rfn) if the enr's
    /// liveness delay has expired
    pub async fn process_enr(&mut self, enr: Enr) {
        // ping for liveliness check
        if !self.liveness_check(enr.clone()).await {
            return;
        }
        // iterate peers routing table via rfn over various distances
        for distance in 245..257 {
            let Ok(result) = self
                .find_nodes(&self.client, enr.clone(), vec![distance])
                .await
            else {
                warn!("Find nodes request failed for enr: {}", enr);
                continue;
            };
            for found_enr in result {
                let _ = self.liveness_check(found_enr).await;
            }
        }
    }

    // Only perform liveness check on enrs if their deadline is up,
    // since the same enr might appear multiple times between the
    // routing tables of different peers.
    pub async fn liveness_check(&mut self, enr: Enr) -> bool {
        // skip if client type is filtered
        let client_type = ClientType::from(&enr);
        if self.filter_clients.contains(&client_type) {
            return false;
        }

        // if enr is already registered, check if delay map deadline has expired
        if let Some(deadline) = self.peers.deadline(&enr.node_id().raw()) {
            if Instant::now() < deadline {
                return false;
            }
        }

        match self.ping(&self.client, enr.clone()).await {
            Ok(pong_info) => {
                let data_radius = Distance::from(U256::from(pong_info.data_radius));
                self.peers.insert(enr.node_id().raw(), (enr, data_radius));
                true
            }
            Err(_) => {
                self.peers.remove(&enr.node_id().raw());
                false
            }
        }
    }

    // Look up all known interested enrs for a given content id
    pub fn get_interested_enrs(&self, content_id: [u8; 32]) -> Result<Vec<Enr>, CensusError> {
        if self.peers.is_empty() {
            error!(
                "No known peers in {} census, unable to offer.",
                self.subnetwork
            );
            return Err(CensusError::NoPeers);
        }
        Ok(self
            .peers
            .iter()
            .filter_map(|(node_id, (enr, data_radius))| {
                let distance = XorMetric::distance(node_id, &content_id);
                if data_radius >= &distance {
                    Some(enr.clone())
                } else {
                    None
                }
            })
            .choose_multiple(&mut rand::thread_rng(), self.enr_offer_limit))
    }

    async fn ping(&self, client: &HttpClient, enr: Enr) -> anyhow::Result<PongInfo> {
        let result = match self.subnetwork {
            Subnetwork::History => HistoryNetworkApiClient::ping(client, enr).await,
            Subnetwork::State => StateNetworkApiClient::ping(client, enr).await,
            Subnetwork::Beacon => BeaconNetworkApiClient::ping(client, enr).await,
            _ => bail!("Unsupported subnetwork: {}", self.subnetwork),
        };
        result.map_err(|e| anyhow!(e))
    }

    async fn find_nodes(
        &self,
        client: &HttpClient,
        enr: Enr,
        distances: Vec<u16>,
    ) -> anyhow::Result<Vec<Enr>> {
        let result = match self.subnetwork {
            Subnetwork::History => {
                HistoryNetworkApiClient::find_nodes(client, enr, distances).await
            }
            Subnetwork::State => StateNetworkApiClient::find_nodes(client, enr, distances).await,
            Subnetwork::Beacon => BeaconNetworkApiClient::find_nodes(client, enr, distances).await,
            _ => bail!("Unsupported subnetwork: {}", self.subnetwork),
        };
        result.map_err(|e| anyhow!(e))
    }

    async fn recursive_find_nodes(
        &self,
        client: &HttpClient,
        node_id: NodeId,
    ) -> anyhow::Result<Vec<Enr>> {
        let result = match self.subnetwork {
            Subnetwork::History => {
                HistoryNetworkApiClient::recursive_find_nodes(client, node_id).await
            }
            Subnetwork::State => StateNetworkApiClient::recursive_find_nodes(client, node_id).await,
            Subnetwork::Beacon => {
                BeaconNetworkApiClient::recursive_find_nodes(client, node_id).await
            }
            _ => bail!("Unsupported subnetwork: {}", self.subnetwork),
        };
        result.map_err(|e| anyhow!(e))
    }
}
