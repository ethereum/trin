use futures::channel::oneshot;
use tokio::{
    sync::mpsc,
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
    HistoryNetworkApiClient, StateContentKey, StateContentValue, StateNetworkApiClient,
};
use trin_metrics::bridge::BridgeMetricsReporter;

// Each gossip request / piece of content is given a timeout of 120 seconds
const GOSSIP_CONTENT_TIMEOUT: Duration = Duration::from_secs(120);

// Starts the gossip engine with the given parameters. The engine will handle gossip requests
// and offer the requested content to the network. Returns a vector of join handles to the
// spawned tasks used to run the engine.
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
            let mut engine = GossipEngine::new(client.clone(), None, gossip_rx, gossip_mode);
            let engine_handle = tokio::spawn(async move { engine.run().await });
            vec![engine_handle]
        }
        GossipMode::Offer => {
            let mut census = Census::new(client.clone(), census_rx);
            let mut engine =
                GossipEngine::new(client.clone(), Some(census_tx), gossip_rx, gossip_mode);
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
    ) -> Self {
        let metrics = BridgeMetricsReporter::new("gossip_engine".to_string(), "direct");
        // We are using a semaphore to limit the amount of active gossip transfers to make sure
        // we don't overwhelm the trin client
        Self {
            client,
            census_tx,
            request_channel,
            mode,
            metrics,
        }
    }

    pub async fn run(&mut self) {
        loop {
            tokio::select! {
                Some(request) = self.request_channel.recv() => {
                    let client = self.client.clone();
                    let metrics = self.metrics.clone();
                    match self.mode {
                        GossipMode::Gossip => {
                            tokio::spawn(async move {
                                if timeout(
                                    GOSSIP_CONTENT_TIMEOUT,
                                    handle_gossip(request, client, metrics),
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
                                        handle_offer(request, client, census_tx, metrics),
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

async fn handle_gossip(request: GossipRequest, client: HttpClient, metrics: BridgeMetricsReporter) {
    // i think we can remove all the timers here and change all original ones back
    let timer = metrics.start_process_timer("handle_gossip");
    match request {
        GossipRequest::History(request) => {
            let key = request.content_key.clone();
            let gossip_report =
                history_trace_gossip(client, key.clone(), request.content_value).await;
            // what stats?
            let _ = request.resp_tx.send(true);
            let stats = ContentStats::from(gossip_report);
            info!("GossipReport(history): key: {key}, stats: {stats}");
            debug!("GossipReport(history): key: {key}, stats: {stats:?}");
        }
        GossipRequest::State(request) => {
            let key = request.content_key.clone();
            let gossip_report =
                state_trace_gossip(client, key.clone(), request.content_value).await;
            let stats = ContentStats::from(gossip_report);
            let _ = request.resp_tx.send(true);
            info!("GossipReport(state): key: {key}, stats: {stats}");
            debug!("GossipReport(state): key: {key}, stats: {stats:?}");
        }
        GossipRequest::Beacon(request) => {
            let key = request.content_key.clone();
            let gossip_report =
                beacon_trace_gossip(client, key.clone(), request.content_value).await;
            let stats = ContentStats::from(gossip_report);
            let _ = request.resp_tx.send(true);
            info!("GossipReport(beacon): key: {key}, stats: {stats}");
            debug!("GossipReport(beacon): key: {key}, stats: {stats:?}");
        }
    }
    metrics.stop_process_timer(timer);
}

async fn handle_offer(
    request: GossipRequest,
    client: HttpClient,
    census_tx: mpsc::UnboundedSender<EnrsRequest>,
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
    let mut handles = vec![];
    let (content_key, content_value, resp_tx) = match request {
        GossipRequest::History(request) => (
            ContentKey::History(request.content_key.clone()),
            request.content_value.encode(),
            request.resp_tx,
        ),
        GossipRequest::State(request) => (
            ContentKey::State(request.content_key.clone()),
            request.content_value.encode(),
            request.resp_tx,
        ),
        GossipRequest::Beacon(request) => (
            ContentKey::Beacon(request.content_key.clone()),
            request.content_value.encode(),
            request.resp_tx,
        ),
    };
    for node in enrs.clone() {
        let client = client.clone();
        let content_key = content_key.clone();
        let content_value = content_value.clone();
        let handle: JoinHandle<Option<Enr>> = tokio::spawn(async move {
            let mut result = None;
            match content_key {
                ContentKey::History(key) => {
                    if let Ok(offer_result) = HistoryNetworkApiClient::trace_offer(
                        &client,
                        node.clone(),
                        key,
                        content_value,
                    )
                    .await
                    {
                        if offer_result {
                            result = Some(node);
                        }
                    }
                }
                ContentKey::State(key) => {
                    if let Ok(offer_result) = StateNetworkApiClient::trace_offer(
                        &client,
                        node.clone(),
                        key,
                        content_value,
                    )
                    .await
                    {
                        if offer_result {
                            result = Some(node);
                        }
                    }
                }
                ContentKey::Beacon(key) => {
                    if let Ok(offer_result) = BeaconNetworkApiClient::trace_offer(
                        &client,
                        node.clone(),
                        key,
                        content_value,
                    )
                    .await
                    {
                        if offer_result {
                            result = Some(node);
                        }
                    }
                }
            };
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
    // ...?
    // this is just to signal that the gossip process is complete... change to ()?
    let _ = resp_tx.send(true);
    info!(
        "GossipReport: key: {:?}, transferred_enrs: {} / {}",
        content_key,
        transferred_enrs.len(),
        enrs.len()
    );
    debug!(
        "GossipReport: key: {:?}, transferred_enrs: {:?}, failed_enrs: {:?}",
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

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum GossipRequest {
    History(HistoryRequest),
    State(StateRequest),
    Beacon(BeaconRequest),
}

#[derive(Debug)]
pub struct HistoryRequest {
    content_key: HistoryContentKey,
    content_value: HistoryContentValue,
    resp_tx: oneshot::Sender<bool>,
}

#[derive(Debug)]
pub struct StateRequest {
    content_key: StateContentKey,
    content_value: StateContentValue,
    resp_tx: oneshot::Sender<bool>,
}

#[derive(Debug)]
pub struct BeaconRequest {
    content_key: BeaconContentKey,
    content_value: BeaconContentValue,
    resp_tx: oneshot::Sender<bool>,
}

impl GossipRequest {
    fn content_key(&self) -> ContentKey {
        match self {
            GossipRequest::History(request) => ContentKey::History(request.content_key.clone()),
            GossipRequest::State(request) => ContentKey::State(request.content_key.clone()),
            GossipRequest::Beacon(request) => ContentKey::Beacon(request.content_key.clone()),
        }
    }
}

impl
    From<(
        HistoryContentKey,
        HistoryContentValue,
        oneshot::Sender<bool>,
    )> for GossipRequest
{
    fn from(
        (content_key, content_value, resp_tx): (
            HistoryContentKey,
            HistoryContentValue,
            oneshot::Sender<bool>,
        ),
    ) -> Self {
        GossipRequest::History(HistoryRequest {
            content_key,
            content_value,
            resp_tx,
        })
    }
}

impl From<(StateContentKey, StateContentValue, oneshot::Sender<bool>)> for GossipRequest {
    fn from(
        (content_key, content_value, resp_tx): (
            StateContentKey,
            StateContentValue,
            oneshot::Sender<bool>,
        ),
    ) -> Self {
        GossipRequest::State(StateRequest {
            content_key,
            content_value,
            resp_tx,
        })
    }
}

impl From<(BeaconContentKey, BeaconContentValue, oneshot::Sender<bool>)> for GossipRequest {
    fn from(
        (content_key, content_value, resp_tx): (
            BeaconContentKey,
            BeaconContentValue,
            oneshot::Sender<bool>,
        ),
    ) -> Self {
        GossipRequest::Beacon(BeaconRequest {
            content_key,
            content_value,
            resp_tx,
        })
    }
}

pub struct EnrsRequest {
    pub content_key: ContentKey,
    pub resp_tx: oneshot::Sender<Vec<Enr>>,
}
