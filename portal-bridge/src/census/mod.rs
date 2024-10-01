use ethportal_api::{
    jsonrpsee::http_client::HttpClient, BeaconContentKey, Enr, HistoryContentKey,
    OverlayContentKey, StateContentKey,
};
use futures::{channel::oneshot, StreamExt};
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::cli::BridgeConfig;
use network::{Network, Subnetwork};

mod network;

/// The error that occured in [Census].
#[derive(Error, Debug)]
pub enum CensusError {
    #[error("No peers found in Census")]
    NoPeers,
    #[error("Failed to initialize Census")]
    FailedInitialization,
}

/// The request for ENRs that should be offered the content.
pub struct EnrsRequest {
    pub content_key: ContentKey,
    pub resp_tx: oneshot::Sender<Vec<Enr>>,
}

/// The enum for network specific content key
#[derive(Debug, Clone)]
pub enum ContentKey {
    History(HistoryContentKey),
    State(StateContentKey),
    Beacon(BeaconContentKey),
}

/// The maximum number of enrs to return in a response,
/// limiting the number of OFFER requests spawned by the bridge
/// for each piece of content
pub const ENR_OFFER_LIMIT: usize = 4;

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
    pub fn new(
        client: HttpClient,
        census_rx: mpsc::UnboundedReceiver<EnrsRequest>,
        bridge_config: &BridgeConfig,
    ) -> Self {
        Self {
            history: Network::new(client.clone(), Subnetwork::History, bridge_config),
            state: Network::new(client.clone(), Subnetwork::State, bridge_config),
            beacon: Network::new(client.clone(), Subnetwork::Beacon, bridge_config),
            census_rx,
        }
    }
}

impl Census {
    pub async fn init(&mut self) -> Result<(), CensusError> {
        // currently, the census is only initialized for the state network
        // only initialized networks will yield inside `run()` loop
        self.state.init().await;
        if self.state.peers.is_empty() {
            return Err(CensusError::FailedInitialization);
        }
        Ok(())
    }

    pub async fn run(&mut self) {
        loop {
            // Randomly selects between what available task is ready
            // and executes it. Ensures that the census will continue
            // to update while it handles a stream of enr requests.
            tokio::select! {
                // handle enrs request
                Some(request) = self.census_rx.recv() => {
                    match self.get_interested_enrs(request.content_key).await {
                        Ok(enrs) => {
                            if let Err(err) = request.resp_tx.send(enrs) {
                                error!("Error sending enrs response: {err:?}");
                            }
                        }
                        Err(_) => {
                            error!("No peers found in census, restarting initialization.");
                            self.state.init().await;
                            if let Err(err) = request.resp_tx.send(Vec::new()) {
                                error!("Error sending enrs response: {err:?}");
                            }
                        }
                    }
                }
                Some(Ok(known_enr)) = self.history.peers.next() => {
                    self.history.process_enr(known_enr.1.0).await;
                    info!("Updated history census: found peers: {}", self.history.peers.len());
                }
                // yield next known state peer and ping for liveness
                Some(Ok(known_enr)) = self.state.peers.next() => {
                    self.state.process_enr(known_enr.1.0).await;
                    info!("Updated state census: found peers: {}", self.state.peers.len());
                }
                Some(Ok(known_enr)) = self.beacon.peers.next() => {
                    self.beacon.process_enr(known_enr.1.0).await;
                    info!("Updated beacon census: found peers: {}", self.beacon.peers.len());
                }
            }
        }
    }

    pub async fn get_interested_enrs(
        &self,
        content_key: ContentKey,
    ) -> Result<Vec<Enr>, CensusError> {
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
