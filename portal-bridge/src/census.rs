use alloy_primitives::U256;
use anyhow::anyhow;
use delay_map::HashMapDelay;
use discv5::enr::NodeId;
use futures::StreamExt;
use tokio::{sync::mpsc, time::Duration};
use tracing::{error, info};

use crate::{
    gossip_engine::{ContentKey, EnrsRequest},
    types::network::NetworkKind,
};
use ethportal_api::{
    generate_random_remote_enr,
    jsonrpsee::http_client::HttpClient,
    types::{
        distance::{Distance, Metric, XorMetric},
        portal::PongInfo,
    },
    BeaconNetworkApiClient, Enr, HistoryNetworkApiClient, OverlayContentKey, StateNetworkApiClient,
};

// why was this delay chosen?
// we need a somewhat short delay so that the event loop iterated rfn lookups can start
// as soon as possible...
const DELAY: Duration = Duration::from_secs(60);

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
    pub async fn start(&mut self, subnetworks: Vec<NetworkKind>) {
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
                //biased;
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
            peers: HashMapDelay::new(DELAY),
            client,
            subnetwork,
        }
    }

    async fn init(&mut self) {
        // initialize known peers with random rfn lookup
        let random_enr = generate_random_remote_enr().1;
        let Ok(initial_enrs) = self
            .subnetwork
            .recursive_find_nodes(&self.client, random_enr.node_id())
            .await
        else {
            panic!("Failed to initialize network censusxxxx");
        };

        for enr in initial_enrs {
            info!("xxx loop peers: {:?}", self.peers.len());
            self.iterate_rfn(enr.clone()).await;
        }
        // the goal of initializing the census is to reach a "complete"
        // view of the entire network, so that gossip modes that are short lived
        // can be effective (eg. gossiping a single block).
        //
        // census is considered initialized when no new peers
        // are found in a single iteration...
        // the census will continue to iterate through the peers after "initialization"
        // the initialization is just to reach a critical mass of peers so that gossip
        // can be effectively performed
        //let mut initialized = false;
        info!("pre-initialization peers: {:?}", self.peers.len());
        /* while !initialized { */
        /* let initial_peers = self.peers.len(); */
        /* let peers = self */
        /* .peers */
        /* .iter() */
        /* .map(|peer| peer.1 .0.clone()) */
        /* .collect::<Vec<_>>(); */
        /* for peer in peers { */
        /* self.iterate_rfn(peer.clone()).await; */
        /* } */
        /* info!("post initialization peers: {:?}", self.peers.len()); */
        /* if self.peers.len() == initial_peers { */
        /* info!( */
        /* "Census ({:?}) initialized: total peers: {}", */
        /* self.subnetwork, */
        /* self.peers.len() */
        /* ); */
        /* initialized = true; */
        /* } else { */
        /* let new_peers = self.peers.len() - initial_peers; */
        /* info!( */
        /* "Census ({:?}) initializing: found new peers: {} / {}", */
        /* self.subnetwork, */
        /* new_peers, */
        /* self.peers.len() */
        /* ); */
        /* } */
        /* } */
    }

    async fn process_enr(&mut self, enr: Enr) {
        // ping for liveliness check
        if !self.liveness_check(enr.clone()).await {
            return;
        }
        // iterate rfn
        self.iterate_rfn(enr).await;
    }

    // iterate rfn of peer over various distances
    async fn iterate_rfn(&mut self, enr: Enr) {
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

    async fn liveness_check(&mut self, enr: Enr) -> bool {
        // only perform liveness check on enrs if their deadline is up..
        // since the same enr might appear multiple times in the rfn lookup
        if let Some(deadline) = self.peers.deadline(&enr.node_id().raw()) {
            if tokio::time::Instant::now() < deadline {
                return false;
            }
        }

        match self.subnetwork.ping(&self.client, enr.clone()).await {
            Ok(pong_info) => {
                // update data radius
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

    // look up all interested enrs for a given content key
    async fn get_interested_enrs(&self, content_id: [u8; 32]) -> Vec<Enr> {
        self.peers
            .iter()
            .filter_map(|(node_id, (enr, data_radius))| {
                // if content_key is within data radius
                let distance = XorMetric::distance(node_id, &content_id);
                let data_radius = Distance::from(U256::from(*data_radius));
                if data_radius >= distance {
                    Some(enr.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<Enr>>()
            .into_iter()
            .filter(|enr| {
                // filter out shisui enrs
                enr.get("c")
                    .and_then(|v| String::from_utf8(v.to_vec()).ok())
                    != Some("shisui".to_string())
            })
            .collect()
    }
}

/// The subnetwork enum represents the different subnetworks that the census
/// can operate on, and forwards requests to the respective overlay network.
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
