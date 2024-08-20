use std::sync::Arc;

use futures::channel::oneshot;
use tokio::{
    sync::{mpsc, Semaphore},
    task::JoinHandle,
    time::{timeout, Duration},
};
use tracing::{debug, error, info, warn};

use crate::{
    census::Census,
    cli::GossipMode,
    gossip::{beacon_trace_gossip, history_trace_gossip, state_trace_gossip},
    stats::ContentStats,
    types::network::NetworkKind,
};
use ethportal_api::{
    jsonrpsee::http_client::HttpClient, BeaconContentKey, BeaconContentValue,
    BeaconNetworkApiClient, ContentValue, Enr, HistoryContentKey, HistoryContentValue,
    HistoryNetworkApiClient, OverlayContentKey, StateContentKey, StateContentValue,
    StateNetworkApiClient,
};
use trin_metrics::bridge::BridgeMetricsReporter;

// Each gossip request / piece of content is given a timeout of 120 seconds
const GOSSIP_CONTENT_TIMEOUT: Duration = Duration::from_secs(120);

pub async fn run_gossip_engine(
    gossip_rx: mpsc::UnboundedReceiver<GossipRequest>,
    client: HttpClient,
    subnetworks: Vec<NetworkKind>,
    gossip_mode: GossipMode,
    gossip_limit: usize,
) -> Vec<JoinHandle<()>> {
    info!(
        "Starting gossip engine: Mode: {:?} Subnetworks: {:?} Gossip Limit: {}",
        gossip_mode, subnetworks, gossip_limit
    );
    let (census_tx, census_rx) = mpsc::unbounded_channel();
    match gossip_mode {
        GossipMode::Gossip => {
            let mut engine =
                GossipEngine::new(client.clone(), None, gossip_rx, gossip_mode, gossip_limit);
            let engine_handle = tokio::spawn(async move { engine.run().await });
            vec![engine_handle]
        }
        GossipMode::Offer => {
            let mut census = Census::new(client.clone(), census_rx);
            let mut engine = GossipEngine::new(
                client.clone(),
                Some(census_tx),
                gossip_rx,
                gossip_mode,
                gossip_limit,
            );
            census.start(subnetworks).await;
            let census_handle = tokio::spawn(async move { census.run().await });
            let engine_handle = tokio::spawn(async move { engine.run().await });
            vec![census_handle, engine_handle]
        }
    }
}

/// The gossip engine is responsible for handling gossip requests and offering the
/// requested content to the network. If 'offer' mode is enabled, the engine will
/// also maintain a census of all the peers live in the network.
pub struct GossipEngine {
    client: HttpClient,
    semaphore: Arc<Semaphore>,
    metrics: BridgeMetricsReporter,
    request_channel: mpsc::UnboundedReceiver<GossipRequest>,
    mode: GossipMode,
    census_tx: Option<mpsc::UnboundedSender<EnrsRequest>>,
}

impl GossipEngine {
    pub fn new(
        client: HttpClient,
        census_tx: Option<mpsc::UnboundedSender<EnrsRequest>>,
        request_channel: mpsc::UnboundedReceiver<GossipRequest>,
        mode: GossipMode,
        gossip_limit: usize,
    ) -> Self {
        let metrics = BridgeMetricsReporter::new("gossip_engine".to_string(), "direct");
        // We are using a semaphore to limit the amount of active gossip transfers to make sure
        // we don't overwhelm the trin client
        let semaphore = Arc::new(Semaphore::new(gossip_limit));
        Self {
            client,
            census_tx,
            semaphore,
            request_channel,
            mode,
            metrics,
        }
    }

    pub async fn run(&mut self) {
        loop {
            tokio::select! {
                Some(request) = self.request_channel.recv() => {
                    let semaphore = self.semaphore.clone();
                    let client = self.client.clone();
                    let metrics = self.metrics.clone();
                    match self.mode {
                        GossipMode::Gossip => {
                            tokio::spawn(async move {
                                if timeout(
                                    GOSSIP_CONTENT_TIMEOUT,
                                    handle_gossip(request, client, semaphore, metrics),
                                ).await.is_err() {
                                    error!("Timeout handling gossip request, this is an indication that a bug is present");
                                }
                            });
                        },
                        GossipMode::Offer => {
                            if let Some(census_tx) = self.census_tx.clone() {
                                tokio::spawn(async move {
                                    if timeout(
                                        GOSSIP_CONTENT_TIMEOUT,
                                        handle_offer(request, client, census_tx, semaphore, metrics),
                                    ).await.is_err() {
                                        error!("Timeout handling offer request, this is an indication that a bug is present");
                                    }
                                });
                            } else {
                                error!("Census tx channel not initialized but received an offer request! Invalid config.");
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn handle_gossip(
    request: GossipRequest,
    client: HttpClient,
    semaphore: Arc<tokio::sync::Semaphore>,
    metrics: BridgeMetricsReporter,
) {
    let timer = metrics.start_process_timer("handle_gossip");
    let permit = semaphore.acquire_owned().await;
    match request {
        GossipRequest::History((key, value)) => {
            let gossip_report = history_trace_gossip(client, key.clone(), value).await;
            let stats = ContentStats::from(gossip_report);
            info!("GossipReport(history): key: {key}, stats: {stats}");
            debug!("GossipReport(history): key: {key}, stats: {stats:?}");
        }
        GossipRequest::State((key, value)) => {
            let gossip_report = state_trace_gossip(client, key.clone(), value).await;
            let stats = ContentStats::from(gossip_report);
            info!("GossipReport(state): key: {key}, stats: {stats}");
            debug!("GossipReport(state): key: {key}, stats: {stats:?}");
        }
        GossipRequest::Beacon((key, value)) => {
            let gossip_report = beacon_trace_gossip(client, key.clone(), value).await;
            let stats = ContentStats::from(gossip_report);
            info!("GossipReport(beacon): key: {key}, stats: {stats}");
            debug!("GossipReport(beacon): key: {key}, stats: {stats:?}");
        }
    }
    drop(permit);
    metrics.stop_process_timer(timer);
}

async fn handle_offer(
    request: GossipRequest,
    client: HttpClient,
    census_tx: mpsc::UnboundedSender<EnrsRequest>,
    semaphore: Arc<tokio::sync::Semaphore>,
    metrics: BridgeMetricsReporter,
) {
    let timer = metrics.start_process_timer("handle_offer");
    let (resp_tx, resp_rx) = oneshot::channel();
    let req = EnrsRequest {
        content_key: request.content_key().clone(),
        resp_tx,
    };
    if let Err(err) = census_tx.send(req) {
        warn!("Error sending enrs request to census: {:?}", err);
        return;
    }
    let Ok(enrs) = resp_rx.await else {
        error!("Error receiving enrs response from census, skipping offer.");
        return;
    };
    // todo test semamphore with era1 file....
    let mut handles = vec![];
    for node in enrs.clone() {
        let client = client.clone();
        let request = request.clone();
        let semaphore = semaphore.clone();
        let handle = tokio::spawn(async move {
            let permit = semaphore.acquire_owned().await;
            let mut result = None;
            match request {
                GossipRequest::History((key, value)) => {
                    if let Ok(offer_result) = HistoryNetworkApiClient::trace_offer(
                        &client,
                        node.clone(),
                        key,
                        value.encode(),
                    )
                    .await
                    {
                        if offer_result {
                            result = Some(node);
                        }
                    }
                }
                GossipRequest::State((key, value)) => {
                    if let Ok(offer_result) = StateNetworkApiClient::trace_offer(
                        &client,
                        node.clone(),
                        key,
                        value.encode(),
                    )
                    .await
                    {
                        if offer_result {
                            result = Some(node);
                        }
                    }
                }
                GossipRequest::Beacon((key, value)) => {
                    if let Ok(offer_result) = BeaconNetworkApiClient::trace_offer(
                        &client,
                        node.clone(),
                        key,
                        value.encode(),
                    )
                    .await
                    {
                        if offer_result {
                            result = Some(node);
                        }
                    }
                }
            };
            drop(permit);
            result
        });
        handles.push(handle);
    }
    let transferred_enrs: Vec<Enr> = futures::future::join_all(handles)
        .await
        .into_iter()
        .filter_map(|enr_result| if let Ok(enr) = enr_result { enr } else { None })
        .collect();
    let failed_enrs: Vec<Enr> = enrs
        .iter()
        .filter(|enr| !transferred_enrs.contains(enr))
        .cloned()
        .collect();
    let (subnet, content_key) = match request.content_key() {
        ContentKey::History(key) => ("history", key.to_hex()),
        ContentKey::State(key) => ("state", key.to_hex()),
        ContentKey::Beacon(key) => ("beacon", key.to_hex()),
    };
    info!(
        "GossipReport({subnet}): key: {:?}, transferred_enrs: {} / {}",
        content_key,
        transferred_enrs.len(),
        enrs.len()
    );
    debug!(
        "GossipReport({subnet}): key: {:?}, transferred_enrs: {:?}, failed_enrs: {:?}",
        content_key, transferred_enrs, failed_enrs
    );
    metrics.stop_process_timer(timer);
}

#[derive(Debug, Clone)]
pub enum ContentKey {
    History(HistoryContentKey),
    State(StateContentKey),
    Beacon(BeaconContentKey),
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum GossipRequest {
    History((HistoryContentKey, HistoryContentValue)),
    State((StateContentKey, StateContentValue)),
    Beacon((BeaconContentKey, BeaconContentValue)),
}

impl GossipRequest {
    fn content_key(&self) -> ContentKey {
        match self {
            GossipRequest::History((key, _)) => ContentKey::History(key.clone()),
            GossipRequest::State((key, _)) => ContentKey::State(key.clone()),
            GossipRequest::Beacon((key, _)) => ContentKey::Beacon(key.clone()),
        }
    }
}

impl From<(HistoryContentKey, HistoryContentValue)> for GossipRequest {
    fn from((key, value): (HistoryContentKey, HistoryContentValue)) -> Self {
        GossipRequest::History((key, value))
    }
}

impl From<(StateContentKey, StateContentValue)> for GossipRequest {
    fn from((key, value): (StateContentKey, StateContentValue)) -> Self {
        GossipRequest::State((key, value))
    }
}

impl From<(BeaconContentKey, BeaconContentValue)> for GossipRequest {
    fn from((key, value): (BeaconContentKey, BeaconContentValue)) -> Self {
        GossipRequest::Beacon((key, value))
    }
}

pub struct EnrsRequest {
    pub content_key: ContentKey,
    pub resp_tx: oneshot::Sender<Vec<Enr>>,
}
