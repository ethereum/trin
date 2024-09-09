use alloy_primitives::U256;
use anyhow::anyhow;
use delay_map::HashMapDelay;
use discv5::enr::NodeId;
use futures::{channel::oneshot, StreamExt};
use tokio::{
    sync::mpsc,
    time::{Duration, Instant},
};
use tracing::{error, info};

use crate::types::network::NetworkKind;
use ethportal_api::{
    generate_random_remote_enr,
    jsonrpsee::http_client::HttpClient,
    types::{
        distance::{Distance, Metric, XorMetric},
        portal::PongInfo,
    },
    BeaconContentKey, BeaconNetworkApiClient, Enr, HistoryContentKey, HistoryNetworkApiClient,
    OverlayContentKey, StateContentKey, StateNetworkApiClient,
};

/// Ping delay for liveness check of peers in census
/// Two minutes was chosen somewhat arbitrarily, and can be adjusted
/// in the future based on performance
const LIVENESS_CHECK_DELAY: Duration = Duration::from_secs(120);

/// The maximum number of enrs to return in a response,
/// limiting the number of OFFER requests spawned by the bridge
/// for each piece of content
const ENRS_RESPONSE_LIMIT: usize = 8;

/// The census is responsible for maintaining a list of known peers in the network,
/// checking their liveness, updating their data radius, iterating through their
/// rfn to find new peers, and providing interested enrs for a given content key.
pub struct Census {
    history: Network,
    state: Network,
    beacon: Network,
    census_rx: mpsc::UnboundedReceiver<EnrsRequest>,
}

impl Census {
    pub fn new(client: HttpClient, census_rx: mpsc::UnboundedReceiver<EnrsRequest>) -> Self {
        Self {
            history: Network::new(client.clone(), Subnetwork::History),
            state: Network::new(client.clone(), Subnetwork::State),
            beacon: Network::new(client.clone(), Subnetwork::Beacon),
            census_rx,
        }
    }
}

impl Census {
    pub async fn init(&mut self, subnetworks: Vec<NetworkKind>) {
        let mut handles = vec![];
        if subnetworks.contains(&NetworkKind::History) {
            info!("Initializing history network census");
            handles.push(self.history.init());
        }
        if subnetworks.contains(&NetworkKind::State) {
            info!("Initializing state network census");
            handles.push(self.state.init());
        }
        if subnetworks.contains(&NetworkKind::Beacon) {
            info!("Initializing beacon network census");
            handles.push(self.beacon.init());
        }
        futures::future::join_all(handles).await;
    }

    pub async fn run(&mut self) {
        loop {
            tokio::select! {
                // handle enrs request
                biased;
                Some(request) = self.census_rx.recv() => {
                    let enrs = self.get_interested_enrs(request.content_key).await;
                    if let Err(err) = request.resp_tx.send(enrs) {
                        error!("Error sending enrs response: {err:?}");
                    }
                }
                // yield next known history peer and ping for liveness
                // if network is not initialized, this will never yield
                Some(Ok(known_enr)) = self.history.peers.next() => {
                    self.history.process_enr(known_enr.1.0).await;
                    info!("Updated history census: found peers: {}", self.history.peers.len());
                }
                // yield next known state peer and ping for liveness
                // if network is not initialized, this will never yield
                Some(Ok(known_enr)) = self.state.peers.next() => {
                    self.state.process_enr(known_enr.1.0).await;
                    info!("Updated state census: found peers: {}", self.state.peers.len());
                }
                // yield next known beacon peer and ping for liveness
                // if network is not initialized, this will never yield
                Some(Ok(known_enr)) = self.beacon.peers.next() => {
                    self.beacon.process_enr(known_enr.1.0).await;
                    info!("Updated beacon census: found peers: {}", self.beacon.peers.len());
                }
            }
        }
    }

    pub async fn get_interested_enrs(&self, content_key: ContentKey) -> Vec<Enr> {
        match content_key {
            ContentKey::History(content_key) => {
                self.history
                    .get_interested_enrs(content_key.content_id())
                    .await
            }
            ContentKey::State(content_key) => {
                self.state
                    .get_interested_enrs(content_key.content_id())
                    .await
            }
            ContentKey::Beacon(content_key) => {
                self.beacon
                    .get_interested_enrs(content_key.content_id())
                    .await
            }
        }
    }
}

/// The network struct is responsible for maintaining a list of known peers
/// in the given subnetwork.
struct Network {
    peers: HashMapDelay<[u8; 32], (Enr, U256)>,
    client: HttpClient,
    subnetwork: Subnetwork,
}

impl Network {
    fn new(client: HttpClient, subnetwork: Subnetwork) -> Self {
        Self {
            peers: HashMapDelay::new(LIVENESS_CHECK_DELAY),
            client,
            subnetwork,
        }
    }

    // We initialize a network with a random rfn lookup to get an initial view of the network
    // and then iterate through the rfn of each peer to find new peers. Since this initialization
    // blocks the bridge's gossip feature, there is a tradeoff between the time taken to initialize
    // the census and the time taken to start gossiping. In the future, we might consider updating
    // the initialization process to be considered complete after it has found ~100% of the network
    // peers. However, since the census continues to iterate through the peers after initialization,
    // the initialization is just to reach a critical mass of peers so that gossip can begin.
    async fn init(&mut self) {
        let random_enr = generate_random_remote_enr().1;
        let Ok(initial_enrs) = self
            .subnetwork
            .recursive_find_nodes(&self.client, random_enr.node_id())
            .await
        else {
            panic!("Failed to initialize network census");
        };

        for enr in initial_enrs {
            self.iterate_peer_routing_table(enr.clone()).await;
        }
    }

    /// Only processes an enr (iterating through its rfn) if the enr's
    /// liveness delay has expired
    async fn process_enr(&mut self, enr: Enr) {
        // ping for liveliness check
        if !self.liveness_check(enr.clone()).await {
            return;
        }
        // iterate through the peer's rfn
        self.iterate_peer_routing_table(enr).await;
    }

    // iterate peers routing table via rfn over various distances
    async fn iterate_peer_routing_table(&mut self, enr: Enr) {
        for distance in 245..257 {
            let Ok(result) = self
                .subnetwork
                .find_nodes(&self.client, enr.clone(), vec![distance])
                .await
            else {
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
    async fn liveness_check(&mut self, enr: Enr) -> bool {
        // check if delay map deadline has expired
        if let Some(deadline) = self.peers.deadline(&enr.node_id().raw()) {
            if Instant::now() < deadline {
                return false;
            }
        }

        match self.subnetwork.ping(&self.client, enr.clone()).await {
            Ok(pong_info) => {
                self.peers
                    .insert(enr.node_id().raw(), (enr.clone(), pong_info.data_radius));
                true
            }
            Err(_) => {
                self.peers.remove(&enr.node_id().raw());
                false
            }
        }
    }

    // Look up all known interested enrs for a given content id
    async fn get_interested_enrs(&self, content_id: [u8; 32]) -> Vec<Enr> {
        self.peers
            .iter()
            .filter_map(|(node_id, (enr, data_radius))| {
                let distance = XorMetric::distance(node_id, &content_id);
                let data_radius = Distance::from(U256::from(*data_radius));
                if data_radius >= distance {
                    Some(enr.clone())
                } else {
                    None
                }
            })
            .take(ENRS_RESPONSE_LIMIT)
            .collect()
    }
}

/// The subnetwork enum represents the different subnetworks that the census
/// can operate on, and forwards requests to each respective overlay network.
#[derive(Debug)]
enum Subnetwork {
    History,
    State,
    Beacon,
}

impl Subnetwork {
    async fn ping(&self, client: &HttpClient, enr: Enr) -> anyhow::Result<PongInfo> {
        let result = match self {
            Subnetwork::History => HistoryNetworkApiClient::ping(client, enr).await,
            Subnetwork::State => StateNetworkApiClient::ping(client, enr).await,
            Subnetwork::Beacon => BeaconNetworkApiClient::ping(client, enr).await,
        };
        result.map_err(|e| anyhow!(e))
    }

    async fn find_nodes(
        &self,
        client: &HttpClient,
        enr: Enr,
        distances: Vec<u16>,
    ) -> anyhow::Result<Vec<Enr>> {
        let result = match self {
            Subnetwork::History => {
                HistoryNetworkApiClient::find_nodes(client, enr, distances).await
            }
            Subnetwork::State => StateNetworkApiClient::find_nodes(client, enr, distances).await,
            Subnetwork::Beacon => BeaconNetworkApiClient::find_nodes(client, enr, distances).await,
        };
        result.map_err(|e| anyhow!(e))
    }

    async fn recursive_find_nodes(
        &self,
        client: &HttpClient,
        node_id: NodeId,
    ) -> anyhow::Result<Vec<Enr>> {
        let result = match self {
            Subnetwork::History => {
                HistoryNetworkApiClient::recursive_find_nodes(client, node_id).await
            }
            Subnetwork::State => StateNetworkApiClient::recursive_find_nodes(client, node_id).await,
            Subnetwork::Beacon => {
                BeaconNetworkApiClient::recursive_find_nodes(client, node_id).await
            }
        };
        result.map_err(|e| anyhow!(e))
    }
}

pub struct EnrsRequest {
    pub content_key: ContentKey,
    pub resp_tx: oneshot::Sender<Vec<Enr>>,
}

#[derive(Debug, Clone)]
pub enum ContentKey {
    History(HistoryContentKey),
    State(StateContentKey),
    Beacon(BeaconContentKey),
}
