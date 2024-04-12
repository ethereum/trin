use std::{
    ops::Range,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{anyhow, ensure};
use futures::future::join_all;
use rand::{seq::SliceRandom, thread_rng};
use scraper::{Html, Selector};
use surf::{Client, Config};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::{sleep, timeout, Duration},
};
use tracing::{debug, error, info, warn};
use trin_metrics::bridge::BridgeMetricsReporter;

use crate::{
    api::execution::construct_proof,
    bridge::{
        history::{HEADER_SATURATION_DELAY, SERVE_BLOCK_TIMEOUT},
        utils::lookup_epoch_acc,
    },
    gossip::gossip_history_content,
    stats::{HistoryBlockStats, StatsReporter},
    types::{
        era1::{BlockTuple, Era1},
        mode::{BridgeMode, FourFoursMode},
    },
};
use ethportal_api::{
    jsonrpsee::http_client::HttpClient, types::execution::accumulator::EpochAccumulator,
    BlockBodyKey, BlockHeaderKey, BlockReceiptsKey, EpochAccumulatorKey, HistoryContentKey,
    HistoryContentValue,
};
use trin_validation::{
    accumulator::MasterAccumulator, constants::EPOCH_SIZE, oracle::HeaderOracle,
};

const ERA1_DIR_URL: &str = "https://era1.ethportal.net/";
const ERA1_FILE_COUNT: usize = 1897;

pub struct Era1Bridge {
    pub mode: BridgeMode,
    pub portal_clients: Vec<HttpClient>,
    pub header_oracle: HeaderOracle,
    pub epoch_acc_path: PathBuf,
    pub era1_files: Vec<String>,
    pub http_client: Client,
    pub metrics: BridgeMetricsReporter,
    pub gossip_limit: usize,
}

// todo: validate via checksum, so we don't have to validate content on a per-value basis
impl Era1Bridge {
    pub async fn new(
        mode: BridgeMode,
        portal_clients: Vec<HttpClient>,
        header_oracle: HeaderOracle,
        epoch_acc_path: PathBuf,
        gossip_limit: usize,
    ) -> anyhow::Result<Self> {
        let http_client: Client = Config::new()
            .add_header("Content-Type", "application/xml")
            .expect("to be able to add header")
            .try_into()?;
        let era1_files = get_shuffled_era1_files(&http_client).await?;
        let metrics = BridgeMetricsReporter::new("era1".to_string(), &format!("{mode:?}"));
        Ok(Self {
            mode,
            portal_clients,
            header_oracle,
            epoch_acc_path,
            era1_files,
            http_client,
            metrics,
            gossip_limit,
        })
    }

    pub async fn launch(&self) {
        info!("Launching era1 bridge: {:?}", self.mode);
        match self.mode.clone() {
            BridgeMode::FourFours(FourFoursMode::Random) => self.launch_random().await,
            BridgeMode::FourFours(FourFoursMode::RandomSingle) => {
                self.launch_random_single(None).await
            }
            BridgeMode::FourFours(FourFoursMode::RandomSingleWithFloor(floor)) => {
                self.launch_random_single(Some(floor)).await
            }
            BridgeMode::FourFours(FourFoursMode::Single(epoch)) => self.launch_single(epoch).await,
            BridgeMode::FourFours(FourFoursMode::Range(start, end)) => {
                self.launch_range(start, end).await;
            }
            _ => panic!("4444s bridge only supports 4444s modes."),
        }
        info!("Bridge mode: {:?} complete.", self.mode);
    }

    async fn launch_random(&self) {
        for era1_path in self.era1_files.clone().into_iter() {
            self.gossip_era1(era1_path, None).await;
        }
    }

    async fn launch_single(&self, epoch: u64) {
        let era1_path = self
            .era1_files
            .clone()
            .into_iter()
            .find(|file| file.contains(&format!("mainnet-{epoch:05}-")))
            .expect("to be able to find era1 file");
        self.gossip_era1(era1_path, None).await;
    }

    async fn launch_random_single(&self, floor: Option<u64>) {
        let mut era1_files = self.era1_files.clone().into_iter();
        let era1_path = loop {
            let era1_file = era1_files
                .next()
                .expect("to be able to get first era1 file");
            match floor {
                Some(floor) => {
                    let epoch = match get_epoch_from_era1_path(&era1_file) {
                        Ok(epoch) => epoch,
                        Err(e) => panic!("Failed to get epoch from era1 file: {e}"),
                    };
                    if epoch >= floor {
                        break era1_file;
                    }
                }
                None => break era1_file,
            }
        };
        self.gossip_era1(era1_path, None).await;
    }

    async fn launch_range(&self, start: u64, end: u64) {
        let epoch = start / EPOCH_SIZE as u64;
        let era1_path =
            self.era1_files.clone().into_iter().find(|file| {
                file.contains(&format!("mainnet-{epoch:05}-")) && file.contains(".era1")
            });
        let gossip_range = Some(Range { start, end });
        match era1_path {
            Some(path) => self.gossip_era1(path, gossip_range).await,
            None => panic!("4444s bridge couldn't find requested epoch on era1 file server"),
        }
    }

    async fn gossip_era1(&self, era1_path: String, gossip_range: Option<Range<u64>>) {
        info!("Processing era1 file at path: {era1_path:?}");
        // We are using a semaphore to limit the amount of active gossip transfers to make sure
        // we don't overwhelm the trin client
        let gossip_send_semaphore = Arc::new(Semaphore::new(self.gossip_limit));

        let raw_era1 = self
            .http_client
            .get(era1_path.clone())
            .recv_bytes()
            .await
            .unwrap_or_else(|_| panic!("unable to read era1 file at path: {era1_path:?}"));
        let epoch_index = match get_epoch_from_era1_path(&era1_path) {
            Ok(epoch) => epoch,
            Err(e) => {
                panic!("Failed to get epoch from era1 file: {e}");
            }
        };
        let epoch_acc = match self.get_epoch_acc(epoch_index).await {
            Ok(epoch_acc) => epoch_acc,
            Err(e) => {
                error!("Failed to get epoch acc for epoch: {epoch_index}, error: {e}");
                return;
            }
        };
        let master_acc = Arc::new(self.header_oracle.master_acc.clone());
        info!("Era1 file read successfully, gossiping block tuples for epoch: {epoch_index}");
        let mut serve_block_tuple_handles = vec![];
        for block_tuple in Era1::iter_tuples(raw_era1) {
            let block_number = block_tuple.header.header.number;
            if let Some(range) = gossip_range.clone() {
                if !range.contains(&block_number) {
                    continue;
                }
            }
            let permit = gossip_send_semaphore
                .clone()
                .acquire_owned()
                .await
                .expect("to be able to acquire semaphore");
            self.metrics.report_current_block(block_number as i64);
            let serve_block_tuple_handle = Self::spawn_serve_block_tuple(
                self.portal_clients.clone(),
                block_tuple,
                epoch_acc.clone(),
                master_acc.clone(),
                permit,
                self.metrics.clone(),
            );
            serve_block_tuple_handles.push(serve_block_tuple_handle);
        }
        // Wait till all block tuples are done gossiping.
        // This can't deadlock, because the tokio::spawn has a timeout.
        join_all(serve_block_tuple_handles).await;
    }

    async fn get_epoch_acc(&self, epoch_index: u64) -> anyhow::Result<Arc<EpochAccumulator>> {
        let (epoch_hash, epoch_acc) = lookup_epoch_acc(
            epoch_index,
            &self.header_oracle.master_acc,
            &self.epoch_acc_path,
        )
        .await?;
        // Gossip epoch acc to network if found locally
        let content_key = HistoryContentKey::EpochAccumulator(EpochAccumulatorKey { epoch_hash });
        let content_value = HistoryContentValue::EpochAccumulator(epoch_acc.clone());
        // create unique stats for epoch accumulator, since it's rarely gossiped
        let block_stats = Arc::new(Mutex::new(HistoryBlockStats::new(
            epoch_index * EPOCH_SIZE as u64,
        )));
        debug!("Built EpochAccumulator for Epoch #{epoch_index:?}: now gossiping.");
        // spawn gossip in new thread to avoid blocking
        let portal_clients = self.portal_clients.clone();
        tokio::spawn(async move {
            if let Err(msg) =
                gossip_history_content(&portal_clients, content_key, content_value, block_stats)
                    .await
            {
                warn!("Failed to gossip epoch accumulator: {msg}");
            }
        });
        Ok(Arc::new(epoch_acc))
    }

    fn spawn_serve_block_tuple(
        portal_clients: Vec<HttpClient>,
        block_tuple: BlockTuple,
        epoch_acc: Arc<EpochAccumulator>,
        master_acc: Arc<MasterAccumulator>,
        permit: OwnedSemaphorePermit,
        metrics: BridgeMetricsReporter,
    ) -> JoinHandle<()> {
        let number = block_tuple.header.header.number;
        info!("Spawning serve_block_tuple for block at height: {number}",);
        let block_stats = Arc::new(Mutex::new(HistoryBlockStats::new(number)));
        tokio::spawn(async move {
            let timer = metrics.start_process_timer("spawn_serve_block_tuple");
            match timeout(
                SERVE_BLOCK_TIMEOUT,
                Self::serve_block_tuple(
                    portal_clients,
                    block_tuple,
                    epoch_acc,
                    master_acc,
                    block_stats.clone(),
                    metrics.clone()
                )).await
                {
                Ok(result) => match result {
                    Ok(_) => {
                        debug!("Done serving block: {number}");
                        if let Ok(stats) = block_stats.lock() {
                            stats.report();
                        }
                    }
                    Err(msg) => warn!("Error serving block: {number}: {msg:?}"),
                },
                Err(_) => error!("serve_full_block() timed out on height {number}: this is an indication a bug is present")
            };
            drop(permit);
            metrics.stop_process_timer(timer);
        })
    }

    async fn serve_block_tuple(
        portal_clients: Vec<HttpClient>,
        block_tuple: BlockTuple,
        epoch_acc: Arc<EpochAccumulator>,
        master_acc: Arc<MasterAccumulator>,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
        metrics: BridgeMetricsReporter,
    ) -> anyhow::Result<()> {
        info!(
            "Serving block tuple at height: {}",
            block_tuple.header.header.number
        );
        let timer = metrics.start_process_timer("construct_and_gossip_header");
        match Self::construct_and_gossip_header(
            portal_clients.clone(),
            block_tuple.clone(),
            epoch_acc,
            master_acc,
            block_stats.clone(),
        )
        .await
        {
            Ok(_) => {
                metrics.report_gossip_success(true, "header");
                debug!(
                    "Successfully served block tuple header at height: {:?}",
                    block_tuple.header.header.number
                )
            }
            Err(msg) => {
                metrics.report_gossip_success(false, "header");
                warn!(
                    "Error serving block tuple header at height, will not gossip remaining block content: {:?} - {:?}",
                    block_tuple.header.header.number, msg
                );
                // We actually do want to cut off the gossip for body / receipts if header fails,
                // since the header might fail validation and we don't want to serve the rest of the
                // block. A future improvement would be to have a more fine-grained error
                // handling and only cut off gossip if header fails validation
                metrics.stop_process_timer(timer);
                return Ok(());
            }
        }
        metrics.stop_process_timer(timer);
        // Sleep for 10 seconds to allow headers to saturate network,
        // since they must be available for body / receipt validation.
        sleep(Duration::from_secs(HEADER_SATURATION_DELAY)).await;
        let timer = metrics.start_process_timer("construct_and_gossip_block_body");
        match Self::construct_and_gossip_block_body(
            portal_clients.clone(),
            block_tuple.clone(),
            block_stats.clone(),
        )
        .await
        {
            Ok(_) => {
                metrics.report_gossip_success(true, "block_body");
                debug!(
                    "Successfully served block body at height: {:?}",
                    block_tuple.header.header.number
                )
            }
            Err(msg) => {
                metrics.report_gossip_success(false, "block_body");
                warn!(
                    "Error serving block body at height: {:?} - {:?}",
                    block_tuple.header.header.number, msg
                )
            }
        }
        metrics.stop_process_timer(timer);
        let timer = metrics.start_process_timer("construct_and_gossip_receipts");
        match Self::construct_and_gossip_receipts(
            portal_clients.clone(),
            block_tuple.clone(),
            block_stats.clone(),
        )
        .await
        {
            Ok(_) => {
                metrics.report_gossip_success(true, "receipt");
                debug!(
                    "Successfully served block receipts at height: {:?}",
                    block_tuple.header.header.number
                )
            }
            Err(msg) => {
                metrics.report_gossip_success(false, "receipt");
                warn!(
                    "Error serving block receipts at height: {:?} - {:?}",
                    block_tuple.header.header.number, msg
                )
            }
        }
        metrics.stop_process_timer(timer);
        Ok(())
    }

    async fn construct_and_gossip_header(
        portal_clients: Vec<HttpClient>,
        block_tuple: BlockTuple,
        epoch_acc: Arc<EpochAccumulator>,
        master_acc: Arc<MasterAccumulator>,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
    ) -> anyhow::Result<()> {
        debug!(
            "Serving block header at height: {}",
            block_tuple.header.header.number
        );
        let header = block_tuple.header.header;
        // Fetch HeaderRecord from EpochAccumulator for validation
        let header_index = header.number % EPOCH_SIZE as u64;
        let header_record = &epoch_acc[header_index as usize];

        // Validate Header
        let actual_header_hash = header.hash();

        ensure!(
            header_record.block_hash == actual_header_hash,
            "Header hash doesn't match record in local accumulator: {:?} - {:?}",
            actual_header_hash,
            header_record.block_hash
        );

        // Construct HistoryContentKey
        let content_key = HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey {
            block_hash: header.hash().0,
        });
        // Construct HeaderWithProof
        let header_with_proof = construct_proof(header.clone(), &epoch_acc).await?;
        // Double check that the proof is valid
        master_acc.validate_header_with_proof(&header_with_proof)?;
        // Construct HistoryContentValue
        let content_value = HistoryContentValue::BlockHeaderWithProof(header_with_proof);

        gossip_history_content(
            // remove borrow
            &portal_clients,
            content_key,
            content_value,
            block_stats,
        )
        .await
    }

    async fn construct_and_gossip_block_body(
        portal_clients: Vec<HttpClient>,
        block_tuple: BlockTuple,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
    ) -> anyhow::Result<()> {
        debug!(
            "Serving block body at height: {}",
            block_tuple.header.header.number
        );
        let header = block_tuple.header.header;
        // Construct HistoryContentKey
        let content_key = HistoryContentKey::BlockBody(BlockBodyKey {
            block_hash: header.hash().0,
        });
        // Construct HistoryContentValue
        let content_value = HistoryContentValue::BlockBody(block_tuple.body.body);
        gossip_history_content(&portal_clients, content_key, content_value, block_stats).await
    }

    async fn construct_and_gossip_receipts(
        portal_clients: Vec<HttpClient>,
        block_tuple: BlockTuple,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
    ) -> anyhow::Result<()> {
        debug!(
            "Serving block receipts at height: {}",
            block_tuple.header.header.number
        );
        let header = block_tuple.header.header;
        // Construct HistoryContentKey
        let content_key = HistoryContentKey::BlockReceipts(BlockReceiptsKey {
            block_hash: header.hash().0,
        });
        // Construct HistoryContentValue
        let content_value = HistoryContentValue::Receipts(block_tuple.receipts.receipts);
        gossip_history_content(&portal_clients, content_key, content_value, block_stats).await
    }
}

/// Fetches era1 files hosted on era1.ethportal.net and shuffles them
async fn get_shuffled_era1_files(http_client: &Client) -> anyhow::Result<Vec<String>> {
    let index_html = http_client
        .get(ERA1_DIR_URL)
        .recv_string()
        .await
        .map_err(|e| anyhow!("{e}"))?;
    let index_html = Html::parse_document(&index_html);
    let selector = Selector::parse("a[href*='mainnet-']").expect("to be able to parse selector");
    let mut era1_files: Vec<String> = index_html
        .select(&selector)
        .map(|element| {
            let href = element
                .value()
                .attr("href")
                .expect("to be able to get href");
            format!("{ERA1_DIR_URL}{href}")
        })
        .collect();
    ensure!(
        era1_files.len() == ERA1_FILE_COUNT,
        format!(
            "invalid era1 source, not enough era1 files found: expected {}, found {}",
            ERA1_FILE_COUNT,
            era1_files.len()
        )
    );
    era1_files.shuffle(&mut thread_rng());
    Ok(era1_files)
}

fn get_epoch_from_era1_path(era1_path: &str) -> anyhow::Result<u64> {
    let era1_path = era1_path.to_string();
    ensure!(era1_path.contains("mainnet-"), "invalid era1 path");
    let epoch_str = era1_path
        .split('-')
        .nth(1)
        .ok_or_else(|| anyhow!("invalid era1 path"))?;
    let epoch = epoch_str.parse::<u64>()?;
    Ok(epoch)
}
