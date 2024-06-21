use std::{
    ops::Range,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use alloy_primitives::B256;
use anyhow::{anyhow, ensure};
use e2store::{
    era1::{BlockTuple, Era1},
    utils::get_shuffled_era1_files,
};
use futures::future::join_all;
use rand::{seq::SliceRandom, thread_rng};
use surf::{Client, Config};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::{sleep, timeout, Duration},
};
use tracing::{debug, error, info, warn};
use trin_metrics::bridge::BridgeMetricsReporter;

use crate::{
    api::execution::{construct_proof, ExecutionApi},
    bridge::{
        history::{HEADER_SATURATION_DELAY, SERVE_BLOCK_TIMEOUT},
        utils::lookup_epoch_acc,
    },
    gossip::gossip_history_content,
    stats::{HistoryBlockStats, StatsReporter},
    types::mode::{BridgeMode, FourFoursMode},
};
use ethportal_api::{
    jsonrpsee::http_client::HttpClient,
    types::{execution::accumulator::EpochAccumulator, history::ContentInfo},
    BlockBodyKey, BlockHeaderKey, BlockReceiptsKey, EpochAccumulatorKey, HistoryContentKey,
    HistoryContentValue, HistoryNetworkApiClient,
};
use trin_validation::{
    constants::EPOCH_SIZE, header_validator::HeaderValidator, oracle::HeaderOracle,
};

pub struct Era1Bridge {
    pub mode: BridgeMode,
    pub portal_client: HttpClient,
    pub header_oracle: HeaderOracle,
    pub epoch_acc_path: PathBuf,
    pub era1_files: Vec<String>,
    pub http_client: Client,
    pub metrics: BridgeMetricsReporter,
    pub gossip_limit: usize,
    pub execution_api: ExecutionApi,
}

// todo: validate via checksum, so we don't have to validate content on a per-value basis
impl Era1Bridge {
    pub async fn new(
        mode: BridgeMode,
        portal_client: HttpClient,
        header_oracle: HeaderOracle,
        epoch_acc_path: PathBuf,
        gossip_limit: usize,
        execution_api: ExecutionApi,
    ) -> anyhow::Result<Self> {
        let http_client: Client = Config::new()
            .add_header("Content-Type", "application/xml")
            .expect("to be able to add header")
            .try_into()?;
        let era1_files = get_shuffled_era1_files(&http_client).await?;
        let metrics = BridgeMetricsReporter::new("era1".to_string(), &format!("{mode:?}"));
        Ok(Self {
            mode,
            portal_client,
            header_oracle,
            epoch_acc_path,
            era1_files,
            http_client,
            metrics,
            gossip_limit,
            execution_api,
        })
    }

    pub async fn launch(&self) {
        info!("Launching era1 bridge: {:?}", self.mode);
        match self.mode.clone() {
            BridgeMode::FourFours(FourFoursMode::Random) => self.launch_random().await,
            BridgeMode::FourFours(FourFoursMode::Hunter(sample_size, threshold)) => {
                if let Err(err) = self.launch_hunter(sample_size, threshold).await {
                    error!("Failed to run hunter mode: {err}");
                }
            }
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
            self.gossip_era1(era1_path, None, false).await;
        }
    }

    async fn launch_hunter(&self, sample_size: u64, threshold: u64) -> anyhow::Result<()> {
        info!("Launching hunter mode with sample size: {sample_size} and threshold: {threshold}");
        let era1_files = self.era1_files.clone().into_iter();
        for era1_path in era1_files {
            let epoch = get_epoch_from_era1_path(&era1_path)?;
            info!("Hunting for missing content inside epoch: {epoch}");
            let block_range = (epoch * EPOCH_SIZE)..((epoch + 1) * EPOCH_SIZE);
            let blocks_to_sample = block_range.clone().collect::<Vec<u64>>();
            let blocks_to_sample =
                blocks_to_sample.choose_multiple(&mut thread_rng(), sample_size as usize);
            let mut hashes_to_sample: Vec<B256> = vec![];
            for block_number in blocks_to_sample {
                let block_hash = self.execution_api.get_block_hash(*block_number).await?;
                hashes_to_sample.push(block_hash);
            }
            let content_keys_to_sample = hashes_to_sample
                .iter()
                .map(|hash| {
                    (
                        HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey {
                            block_hash: hash.0,
                        }),
                        HistoryContentKey::BlockBody(BlockBodyKey { block_hash: hash.0 }),
                        HistoryContentKey::BlockReceipts(BlockReceiptsKey { block_hash: hash.0 }),
                    )
                })
                .collect::<Vec<(HistoryContentKey, HistoryContentKey, HistoryContentKey)>>()
                .iter()
                .flat_map(|(header_key, body_key, receipts_key)| {
                    vec![header_key.clone(), body_key.clone(), receipts_key.clone()]
                })
                .collect::<Vec<HistoryContentKey>>();
            let mut found = 0;
            let hunter_threshold = (content_keys_to_sample.len() as u64 * threshold / 100) as usize;
            for content_key in content_keys_to_sample {
                let result = self
                    .portal_client
                    .recursive_find_content(content_key.clone())
                    .await;
                if let Ok(ContentInfo::Content { .. }) = result {
                    found += 1;
                    if found == hunter_threshold {
                        info!("Hunter found enough content ({hunter_threshold}) to stop hunting in epoch {epoch}");
                        break;
                    }
                }
            }
            if found < hunter_threshold {
                info!("Hunter failed to find enough content ({hunter_threshold}) in epoch {epoch}, launching epoch gossip.");
                self.gossip_era1(era1_path, None, true).await;
            }
        }
        Ok(())
    }

    async fn launch_single(&self, epoch: u64) {
        let era1_path = self
            .era1_files
            .clone()
            .into_iter()
            .find(|file| file.contains(&format!("mainnet-{epoch:05}-")))
            .expect("to be able to find era1 file");
        self.gossip_era1(era1_path, None, false).await;
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
        self.gossip_era1(era1_path, None, false).await;
    }

    async fn launch_range(&self, start: u64, end: u64) {
        let epoch = start / EPOCH_SIZE;
        let era1_path =
            self.era1_files.clone().into_iter().find(|file| {
                file.contains(&format!("mainnet-{epoch:05}-")) && file.contains(".era1")
            });
        let gossip_range = Some(Range { start, end });
        match era1_path {
            Some(path) => self.gossip_era1(path, gossip_range, false).await,
            None => panic!("4444s bridge couldn't find requested epoch on era1 file server"),
        }
    }

    async fn gossip_era1(&self, era1_path: String, gossip_range: Option<Range<u64>>, hunt: bool) {
        info!("Processing era1 file at path: {era1_path:?}");
        // We are using a semaphore to limit the amount of active gossip transfers to make sure
        // we don't overwhelm the trin client
        let gossip_send_semaphore = Arc::new(Semaphore::new(self.gossip_limit));

        let raw_era1 = self
            .http_client
            .get(era1_path.clone())
            .recv_bytes()
            .await
            .unwrap_or_else(|err| {
                panic!("unable to read era1 file at path: {era1_path:?} : {err}")
            });
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
        let header_validator = Arc::new(self.header_oracle.header_validator.clone());
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
                self.portal_client.clone(),
                block_tuple,
                epoch_acc.clone(),
                header_validator.clone(),
                permit,
                self.metrics.clone(),
                hunt,
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
            &self.header_oracle.header_validator.pre_merge_acc,
            &self.epoch_acc_path,
        )
        .await?;
        // Gossip epoch acc to network if found locally
        let content_key = HistoryContentKey::EpochAccumulator(EpochAccumulatorKey { epoch_hash });
        let content_value = HistoryContentValue::EpochAccumulator(epoch_acc.clone());
        // create unique stats for epoch accumulator, since it's rarely gossiped
        let block_stats = Arc::new(Mutex::new(HistoryBlockStats::new(epoch_index * EPOCH_SIZE)));
        debug!("Built EpochAccumulator for Epoch #{epoch_index:?}: now gossiping.");
        // spawn gossip in new thread to avoid blocking
        let portal_client = self.portal_client.clone();
        tokio::spawn(async move {
            if let Err(msg) =
                gossip_history_content(portal_client, content_key, content_value, block_stats).await
            {
                warn!("Failed to gossip epoch accumulator: {msg}");
            }
        });
        Ok(Arc::new(epoch_acc))
    }

    fn spawn_serve_block_tuple(
        portal_client: HttpClient,
        block_tuple: BlockTuple,
        epoch_acc: Arc<EpochAccumulator>,
        header_validator: Arc<HeaderValidator>,
        permit: OwnedSemaphorePermit,
        metrics: BridgeMetricsReporter,
        hunt: bool,
    ) -> JoinHandle<()> {
        let number = block_tuple.header.header.number;
        info!("Spawning serve_block_tuple for block at height: {number}");
        let block_stats = Arc::new(Mutex::new(HistoryBlockStats::new(number)));
        tokio::spawn(async move {
            let timer = metrics.start_process_timer("spawn_serve_block_tuple");
            match timeout(
                SERVE_BLOCK_TIMEOUT,
                Self::serve_block_tuple(
                    portal_client,
                    block_tuple,
                    epoch_acc,
                    header_validator,
                    block_stats.clone(),
                    metrics.clone(),
                    hunt,
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
        portal_client: HttpClient,
        block_tuple: BlockTuple,
        epoch_acc: Arc<EpochAccumulator>,
        header_validator: Arc<HeaderValidator>,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
        metrics: BridgeMetricsReporter,
        hunt: bool,
    ) -> anyhow::Result<()> {
        info!(
            "Serving block tuple at height: {}",
            block_tuple.header.header.number
        );
        let mut gossip_header = true;
        if hunt {
            let header_hash = block_tuple.header.header.hash();
            let header_key = BlockHeaderKey {
                block_hash: header_hash.0,
            };
            let header_content_key = HistoryContentKey::BlockHeaderWithProof(header_key);
            let header_content_info = portal_client
                .recursive_find_content(header_content_key.clone())
                .await;
            if let Ok(ContentInfo::Content { .. }) = header_content_info {
                info!(
                    "Skipping header at height: {} as header already found",
                    block_tuple.header.header.number
                );
                gossip_header = false;
            }
        }
        if gossip_header {
            let timer = metrics.start_process_timer("construct_and_gossip_header");
            match Self::construct_and_gossip_header(
                portal_client.clone(),
                block_tuple.clone(),
                epoch_acc,
                header_validator,
                block_stats.clone(),
            )
            .await
            {
                Ok(_) => {
                    metrics.report_gossip_success(true, "header");
                    info!(
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
                    // We actually do want to cut off the gossip for body / receipts if header
                    // fails, since the header might fail validation and we
                    // don't want to serve the rest of the block. A future
                    // improvement would be to have a more fine-grained error
                    // handling and only cut off gossip if header fails validation
                    metrics.stop_process_timer(timer);
                    return Ok(());
                }
            }
            metrics.stop_process_timer(timer);
            // Sleep for 10 seconds to allow headers to saturate network,
            // since they must be available for body / receipt validation.
            sleep(Duration::from_secs(HEADER_SATURATION_DELAY)).await;
        }
        let mut gossip_body = true;
        if hunt {
            let body_hash = block_tuple.header.header.hash();
            let body_key = BlockBodyKey {
                block_hash: body_hash.0,
            };
            let body_content_key = HistoryContentKey::BlockBody(body_key);
            let body_content_info = portal_client
                .recursive_find_content(body_content_key.clone())
                .await;
            if let Ok(ContentInfo::Content { .. }) = body_content_info {
                info!(
                    "Skipping body at height: {} as body already found",
                    block_tuple.header.header.number
                );
                gossip_body = false;
            }
        }
        if gossip_body {
            let timer = metrics.start_process_timer("construct_and_gossip_block_body");
            match Self::construct_and_gossip_block_body(
                portal_client.clone(),
                block_tuple.clone(),
                block_stats.clone(),
            )
            .await
            {
                Ok(_) => {
                    metrics.report_gossip_success(true, "block_body");
                    info!(
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
        }
        let mut gossip_receipts = true;
        if hunt {
            let receipts_hash = block_tuple.header.header.hash();
            let receipts_key = BlockReceiptsKey {
                block_hash: receipts_hash.0,
            };
            let receipts_content_key = HistoryContentKey::BlockReceipts(receipts_key);
            let receipts_content_info = portal_client
                .recursive_find_content(receipts_content_key.clone())
                .await;
            if let Ok(ContentInfo::Content { .. }) = receipts_content_info {
                info!(
                    "Skipping receipts at height: {} as receipts already found",
                    block_tuple.header.header.number
                );
                gossip_receipts = false;
            }
        };
        if gossip_receipts {
            let timer = metrics.start_process_timer("construct_and_gossip_receipts");
            match Self::construct_and_gossip_receipts(
                portal_client.clone(),
                block_tuple.clone(),
                block_stats.clone(),
            )
            .await
            {
                Ok(_) => {
                    metrics.report_gossip_success(true, "receipt");
                    info!(
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
        }
        Ok(())
    }

    async fn construct_and_gossip_header(
        portal_client: HttpClient,
        block_tuple: BlockTuple,
        epoch_acc: Arc<EpochAccumulator>,
        header_validator: Arc<HeaderValidator>,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
    ) -> anyhow::Result<()> {
        debug!(
            "Serving block header at height: {}",
            block_tuple.header.header.number
        );
        let header = block_tuple.header.header;
        // Fetch HeaderRecord from EpochAccumulator for validation
        let header_index = header.number % EPOCH_SIZE;
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
        header_validator.validate_header_with_proof(&header_with_proof)?;
        // Construct HistoryContentValue
        let content_value = HistoryContentValue::BlockHeaderWithProof(header_with_proof);

        gossip_history_content(portal_client, content_key, content_value, block_stats).await
    }

    async fn construct_and_gossip_block_body(
        portal_client: HttpClient,
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
        gossip_history_content(portal_client, content_key, content_value, block_stats).await
    }

    async fn construct_and_gossip_receipts(
        portal_client: HttpClient,
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
        gossip_history_content(portal_client, content_key, content_value, block_stats).await
    }
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
