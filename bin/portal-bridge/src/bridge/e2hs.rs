use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Instant,
};

use alloy::primitives::B256;
use anyhow::ensure;
use bytes::Bytes;
use clap::Parser;
use e2store::{
    e2hs::{BlockTuple, E2HSMemory},
    utils::get_e2hs_files,
};
use ethportal_api::{
    types::{
        execution::header_with_proof::HeaderWithProof, network::Subnetwork, portal_wire::OfferTrace,
    },
    BlockBody, ContentValue, HistoryContentKey, HistoryContentValue, OverlayContentKey,
    RawContentValue, Receipts,
};
use futures::{
    future::{join_all, JoinAll, Map},
    FutureExt,
};
use itertools::Itertools;
use rand::seq::SliceRandom;
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client,
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::{JoinError, JoinHandle},
    time::{sleep, timeout},
};
use tracing::{debug, error, info, warn};
use trin::handle::SubnetworkOverlays;
use trin_metrics::bridge::BridgeMetricsReporter;
use trin_validation::header_validator::HeaderValidator;

use super::offer_report::{GlobalOfferReport, OfferReport};
use crate::{
    bridge::constants::{HEADER_SATURATION_DELAY, SERVE_BLOCK_TIMEOUT},
    census::{peer::PeerInfo, Census},
    types::range::block_range_to_epochs,
};

pub struct E2HSBridge {
    /// Gossips the content.
    ///
    /// Creates tasks responsible to gossiping the content, but gossip rate is limited with
    /// [Gossiper::offer_semaphore].
    gossiper: Gossiper,
    /// Semaphore used to limit the number of active blocks transfers.
    ///
    /// It has the same number of permits as [Gossiper::offer_semaphore], as there is no need
    /// to gossip more blocks in parallel.
    block_semaphore: Arc<Semaphore>,
    header_validator: HeaderValidator,
    block_range: BlockRange,
    random_fill: bool,
    e2hs_files: HashMap<u64, String>,
    http_client: Client,
}

impl E2HSBridge {
    pub async fn new(
        portal_client: SubnetworkOverlays,
        offer_limit: usize,
        block_range: BlockRange,
        random_fill: bool,
        census: Census,
    ) -> anyhow::Result<Self> {
        let offer_semaphore = Arc::new(Semaphore::new(offer_limit));
        let block_semaphore = Arc::new(Semaphore::new(offer_limit));
        let mode = format!("{}-{}:{}", block_range.start, block_range.end, random_fill);
        let metrics = BridgeMetricsReporter::new("e2hs".to_string(), &mode);
        let http_client = Client::builder()
            .default_headers(HeaderMap::from_iter([(
                CONTENT_TYPE,
                HeaderValue::from_static("application/xml"),
            )]))
            .build()?;
        let e2hs_files = get_e2hs_files(&http_client).await?;
        let global_offer_report = Arc::new(Mutex::new(GlobalOfferReport::default()));
        let gossiper = Gossiper {
            census,
            portal_client,
            metrics,
            global_offer_report,
            offer_semaphore,
        };
        Ok(Self {
            gossiper,
            block_semaphore,
            header_validator: HeaderValidator::new(),
            block_range,
            random_fill,
            e2hs_files,
            http_client,
        })
    }

    pub async fn launch(&self) {
        info!("Launching E2HS bridge");

        let epochs = block_range_to_epochs(self.block_range.start, self.block_range.end);
        let mut epoch_indexes: Vec<u64> = epochs.keys().cloned().sorted().collect();
        if self.random_fill {
            epoch_indexes.shuffle(&mut rand::thread_rng());
        }

        let mut latest_task = None;
        for index in epoch_indexes {
            let block_range = epochs.get(&index).expect("to be able to get block range");

            // Start gossiping epoch
            let task = self.gossip_epoch(index, *block_range).await;

            if let Some(previous_task) = latest_task.replace(task) {
                previous_task.await;
            }
        }

        // Wait for the latest task to finish
        if let Some(latest_task) = latest_task.take() {
            latest_task.await;
        }

        self.gossiper
            .global_offer_report
            .lock()
            .expect("to acquire lock")
            .report();
    }

    /// Gossip single epoch.
    ///
    /// Downloads e2hs file, then validates and gossips each block from the epoch. For each block,
    /// we first obtain `block_permit`, then we spawn a task that gossips it. This controls how
    /// many blocks are gossiped in parallel.
    ///
    /// Returns [JoinAll] of all block gossip tasks.
    async fn gossip_epoch(
        &self,
        epoch_index: u64,
        block_range: Option<(u64, u64)>,
    ) -> JoinAll<Map<JoinHandle<()>, impl FnOnce(Result<(), JoinError>)>> {
        match block_range {
            Some(block_range) => {
                info!("Gossiping block range: {block_range:?} from epoch {epoch_index}")
            }
            None => info!("Gossiping entire epoch {epoch_index}"),
        }

        let raw_e2hs = self.download_e2hs(epoch_index).await;
        let block_stream = E2HSMemory::iter_tuples(&raw_e2hs).expect("to be able to iter tuples");

        let mut tasks = vec![];
        for block_tuple in block_stream {
            let block_number = block_tuple
                .header_with_proof
                .header_with_proof
                .header
                .number;
            if let Some((start, end)) = block_range {
                if block_number < start || block_number > end {
                    debug!("Skipping block {block_number} outside of range");
                    continue;
                }
            }
            if let Err(err) = self.validate_block_tuple(&block_tuple) {
                error!("Failed to validate block tuple: {err:?}");
                continue;
            }

            let gossiper = self.gossiper.clone();
            let block_permit = self.block_semaphore.clone().acquire_owned().await;
            let task = tokio::spawn(async move {
                gossiper.gossip_block(block_number, block_tuple).await;
                drop(block_permit);
            })
            .map(move |task_result| {
                if let Err(err) = task_result {
                    error!(block_number, %err, "Error gossiping block");
                }
            });
            tasks.push(task);
        }
        join_all(tasks)
    }

    async fn download_e2hs(&self, epoch_index: u64) -> Bytes {
        let Some(e2hs_path) = self.e2hs_files.get(&epoch_index) else {
            panic!("Failed to find e2hs file for epoch {epoch_index}");
        };
        self.http_client
            .get(e2hs_path.clone())
            .send()
            .await
            .expect("to be able to send request")
            .bytes()
            .await
            .unwrap_or_else(|err| panic!("unable to read e2hs file at path: {e2hs_path:?} : {err}"))
    }

    fn validate_block_tuple(&self, block_tuple: &BlockTuple) -> anyhow::Result<()> {
        let header_with_proof = &block_tuple.header_with_proof.header_with_proof;
        self.header_validator
            .validate_header_with_proof(header_with_proof)?;
        let body = &block_tuple.body.body;
        body.validate_against_header(&header_with_proof.header)?;
        let receipts = &block_tuple.receipts.receipts;
        ensure!(
            receipts.root() == header_with_proof.header.receipts_root,
            "Receipts root mismatch"
        );
        Ok(())
    }
}

/// Structure that sends offer requests to peers.
///
/// This structure is cheap to clone, which makes it easy to use with tokio tasks.
#[derive(Clone)]
struct Gossiper {
    /// Used to request all interested enrs in the network.
    census: Census,
    /// Used to send RPC request to trin
    portal_client: SubnetworkOverlays,
    /// Records and reports bridge metrics
    metrics: BridgeMetricsReporter,
    /// Global offer report for tallying total performance of history bridge
    global_offer_report: Arc<Mutex<GlobalOfferReport>>,
    /// Semaphore used to limit the number of active offer transfers, in order to make sure we
    /// don't overwhelm the trin client
    offer_semaphore: Arc<Semaphore>,
}

impl Gossiper {
    /// Gossips the all block relate content.
    ///
    /// Gossips BlockHeaderByHash at the start. Afterwards, starts gossiping BlockHeaderByNumber.
    /// It waits for [HEADER_SATURATION_DELAY] after BlockHeaderByHash is gossiped to start
    /// gossiping BlockBody and BlockReceipts.
    ///
    /// Finishes once all content is gossiped.
    async fn gossip_block(&self, block_number: u64, block_tuple: BlockTuple) {
        info!("Serving block tuple for block #{block_number}");
        let BlockTuple {
            header_with_proof,
            body,
            receipts,
        } = block_tuple;
        let block_hash = header_with_proof.header_with_proof.header.hash_slow();

        // Gossip BlockHeaderByHash and wait until it finishes
        if let Err(err) = self
            .start_gossip_header_by_hash_task(
                block_hash,
                header_with_proof.header_with_proof.clone(),
            )
            .await
        {
            error!(%block_hash, %err, "Error while trying to gossip BlockHeaderByHash");
        }

        let mut gossip_tasks = vec![];

        // Start gossiping BlockHeaderByNumber
        gossip_tasks.push(
            self.start_gossip_header_by_number_task(
                block_number,
                header_with_proof.header_with_proof,
            ),
        );

        // Wait until BlockHeaderByHash saturates network,
        // since it must be available for body / receipt validation
        sleep(HEADER_SATURATION_DELAY).await;

        // Start gossiping BlockBody and BlockReceipts
        gossip_tasks.push(self.start_gossip_body_task(block_hash, body.body));
        gossip_tasks.push(self.start_gossip_receipts_task(block_hash, receipts.receipts));

        // Wait until BlockHeaderByNumber, BlockBody and BlockReceipts are gossiped
        join_all(gossip_tasks).await;
    }

    fn start_gossip_header_by_hash_task(
        &self,
        block_hash: B256,
        header_with_proof: HeaderWithProof,
    ) -> JoinHandle<Vec<OfferTrace>> {
        let content_key = HistoryContentKey::new_block_header_by_hash(block_hash);
        let content_value = HistoryContentValue::BlockHeaderWithProof(header_with_proof);
        self.start_gossip_task(content_key, content_value)
    }

    fn start_gossip_header_by_number_task(
        &self,
        block_number: u64,
        header_with_proof: HeaderWithProof,
    ) -> JoinHandle<Vec<OfferTrace>> {
        let content_key = HistoryContentKey::new_block_header_by_number(block_number);
        let content_value = HistoryContentValue::BlockHeaderWithProof(header_with_proof);
        self.start_gossip_task(content_key, content_value)
    }

    fn start_gossip_body_task(
        &self,
        block_hash: B256,
        body: BlockBody,
    ) -> JoinHandle<Vec<OfferTrace>> {
        let content_key = HistoryContentKey::new_block_body(block_hash);
        let content_value = HistoryContentValue::BlockBody(body);
        self.start_gossip_task(content_key, content_value)
    }

    fn start_gossip_receipts_task(
        &self,
        block_hash: B256,
        receipts: Receipts,
    ) -> JoinHandle<Vec<OfferTrace>> {
        let content_key = HistoryContentKey::new_block_receipts(block_hash);
        let content_value = HistoryContentValue::Receipts(receipts);
        self.start_gossip_task(content_key, content_value)
    }

    /// Starts async task that gossips content, retuning [JoinHandle] for it.
    fn start_gossip_task(
        &self,
        content_key: HistoryContentKey,
        content_value: HistoryContentValue,
    ) -> JoinHandle<Vec<OfferTrace>> {
        let executor = self.clone();
        tokio::spawn(async move { executor.gossip_content(content_key, content_value).await })
    }

    /// Spawn individual offer tasks for each interested enr found in Census.
    ///
    /// Returns once all tasks complete.
    async fn gossip_content(
        &self,
        content_key: HistoryContentKey,
        content_value: HistoryContentValue,
    ) -> Vec<OfferTrace> {
        let Ok(peers) = self
            .census
            .select_peers(Subnetwork::History, &content_key.content_id())
        else {
            error!("Failed to request enrs for content key, skipping offer: {content_key:?}");
            return vec![];
        };
        let offer_report = Arc::new(Mutex::new(OfferReport::new(
            content_key.clone(),
            peers.len(),
        )));
        let encoded_content_value = content_value.encode();
        let mut tasks = vec![];
        for peer in peers.clone() {
            let offer_permit = self.acquire_offer_permit().await;
            let offer_report = offer_report.clone();
            let content_key = content_key.clone();
            let raw_content_value = encoded_content_value.clone();

            let gossiper = self.clone();
            tasks.push(tokio::spawn(async move {
                gossiper
                    .send_offer(
                        offer_permit,
                        offer_report,
                        peer,
                        content_key,
                        raw_content_value,
                    )
                    .await
            }));
        }
        join_all(tasks)
            .await
            .into_iter()
            .map(|task_result| match task_result {
                Ok(offer_trace) => offer_trace,
                Err(err) => {
                    error!("Sending offer task failed: {err}");
                    OfferTrace::Failed
                }
            })
            .collect()
    }

    async fn send_offer(
        &self,
        offer_permit: OwnedSemaphorePermit,
        offer_report: Arc<Mutex<OfferReport<HistoryContentKey>>>,
        peer: PeerInfo,
        content_key: HistoryContentKey,
        raw_content_value: RawContentValue,
    ) -> OfferTrace {
        let timer = self.metrics.start_process_timer("history_send_offer");

        let start_time = Instant::now();
        let content_value_size = raw_content_value.len();

        let result = timeout(
            SERVE_BLOCK_TIMEOUT,
            self.portal_client
                .history_overlay()
                .expect("History Network wasn't initialized")
                .overlay
                .send_offer_trace(peer.enr.clone(), content_key.to_bytes(), raw_content_value),
        )
        .await;

        let offer_trace = match result {
            Ok(Ok(result)) => {
                if matches!(result, OfferTrace::Failed) {
                    warn!("Internal error offering to: {}", peer.enr);
                }
                result
            }
            Ok(Err(err)) => {
                warn!("Error offering to: {}, error: {err:?}", peer.enr);
                OfferTrace::Failed
            }
            Err(_) => {
                error!(
                    "trace_offer timed out on history {content_key}: indicating a bug is present"
                );
                OfferTrace::Failed
            }
        };

        self.census.record_offer_result(
            Subnetwork::History,
            peer.enr.node_id(),
            content_value_size,
            start_time.elapsed(),
            &offer_trace,
        );

        // Update report and metrics
        self.global_offer_report
            .lock()
            .expect("to acquire lock")
            .update(&offer_trace);
        offer_report
            .lock()
            .expect("to acquire lock")
            .update(&peer, &offer_trace);

        self.metrics.report_offer(
            match content_key {
                HistoryContentKey::BlockHeaderByHash(_) => "header_by_hash",
                HistoryContentKey::BlockHeaderByNumber(_) => "header_by_number",
                HistoryContentKey::BlockBody(_) => "block_body",
                HistoryContentKey::BlockReceipts(_) => "receipts",
                HistoryContentKey::EphemeralHeadersFindContent(_) => {
                    "ephemeral_headers_find_content"
                }
                HistoryContentKey::EphemeralHeaderOffer(_) => "ephemeral_header_offer",
            },
            &peer.client_type,
            &offer_trace,
        );

        self.metrics.stop_process_timer(timer);
        // Release permit
        drop(offer_permit);

        offer_trace
    }

    async fn acquire_offer_permit(&self) -> OwnedSemaphorePermit {
        self.offer_semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("to be able to acquire semaphore")
    }
}

/// BlockRange used specifically for the E2HS bridge
#[derive(Parser, Debug, Clone)]
pub struct BlockRange {
    pub start: u64,
    pub end: u64,
}

impl FromStr for BlockRange {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('-').collect();
        ensure!(parts.len() == 2, "Invalid block range format");
        let start = parts[0].parse()?;
        let end = parts[1].parse()?;
        Ok(Self { start, end })
    }
}
