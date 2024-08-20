use std::{path::PathBuf, sync::Arc};

use anyhow::bail;
use futures::future::join_all;
use tokio::{
    sync::mpsc::UnboundedSender,
    task::JoinHandle,
    time::{sleep, timeout, Duration},
};
use tracing::{debug, error, info, warn, Instrument};

use crate::{
    api::execution::ExecutionApi,
    bridge::utils::lookup_epoch_acc,
    gossip_engine::GossipRequest,
    types::{full_header::FullHeader, mode::BridgeMode},
    utils::{read_test_assets_from_file, TestAssets},
};
use ethportal_api::{
    types::execution::accumulator::EpochAccumulator, EpochAccumulatorKey, HistoryContentKey,
    HistoryContentValue,
};
use trin_metrics::bridge::BridgeMetricsReporter;
use trin_validation::{
    constants::{EPOCH_SIZE, MERGE_BLOCK_NUMBER},
    oracle::HeaderOracle,
};

// todo: calculate / test optimal saturation delay
pub const HEADER_SATURATION_DELAY: u64 = 10; // seconds
const LATEST_BLOCK_POLL_RATE: u64 = 5; // seconds
pub const SERVE_BLOCK_TIMEOUT: Duration = Duration::from_secs(120);
pub const SERVE_CONTENT_TIMEOUT: Duration = Duration::from_secs(30);

pub struct HistoryBridge {
    pub mode: BridgeMode,
    pub gossip_tx: UnboundedSender<GossipRequest>,
    pub execution_api: ExecutionApi,
    pub header_oracle: HeaderOracle,
    pub epoch_acc_path: PathBuf,
    pub metrics: BridgeMetricsReporter,
}

impl HistoryBridge {
    pub fn new(
        mode: BridgeMode,
        execution_api: ExecutionApi,
        gossip_tx: UnboundedSender<GossipRequest>,
        epoch_acc_path: PathBuf,
    ) -> Self {
        let header_oracle = HeaderOracle::default();
        let metrics = BridgeMetricsReporter::new("history".to_string(), &format!("{mode:?}"));
        Self {
            mode,
            gossip_tx,
            execution_api,
            header_oracle,
            epoch_acc_path,
            metrics,
        }
    }
}

impl HistoryBridge {
    pub async fn launch(&self) {
        info!("Launching bridge mode: {:?}", self.mode);
        match self.mode.clone() {
            BridgeMode::Test(path) => self.launch_test(path).await,
            BridgeMode::Latest => self.launch_latest().await,
            BridgeMode::FourFours(_) => panic!("4444s mode not supported in HistoryBridge."),
            _ => self.launch_backfill().await,
        }
        info!("Bridge mode: {:?} complete.", self.mode);
    }

    async fn launch_test(&self, test_path: PathBuf) {
        let assets: TestAssets = read_test_assets_from_file(test_path);
        let assets = assets
            .into_history_assets()
            .expect("Error parsing history test assets.");

        // test files have no block number data, so we report all gossiped content at height 0.
        for asset in assets.0.into_iter() {
            let gossip_request = GossipRequest::from((
                asset.content_key.clone(),
                asset.content_value().expect("Error getting content value"),
            ));
            if let Err(err) = self.gossip_tx.send(gossip_request) {
                error!("Error sending test history gossip request to gossip engine: {err:?}");
            }
            if let HistoryContentKey::BlockHeaderWithProof(_) = asset.content_key {
                sleep(Duration::from_millis(50)).await;
            }
        }
    }

    // Devops nodes don't have websockets available, so we can't actually poll the latest block.
    // Instead we loop on a short interval and fetch the latest blocks not yet served.
    async fn launch_latest(&self) {
        let mut block_index = self.execution_api.get_latest_block_number().await.expect(
            "Error launching bridge in latest mode. Unable to get latest block from provider.",
        );
        // If a provider returns the same block number and doesn't time out over and over.
        // this indicates the provider is no longer in sync with the chain so we want to long an
        // error
        let mut last_seen_block_counter = 0;
        loop {
            sleep(Duration::from_secs(LATEST_BLOCK_POLL_RATE)).await;
            // If get_latest_block_number(), it is an indiction there is a deadlock bug somewhere in
            // this future call, we know it doesn't happen if we use infura, but it comes up when we
            // use ethpandaops, maybe we are deadlocking if we get a bad http response?
            let latest_block = match timeout(
                Duration::from_secs(LATEST_BLOCK_POLL_RATE),
                self.execution_api.get_latest_block_number(),
            )
            .await
            {
                Ok(result) => match result {
                    Ok(latest_block) => latest_block,
                    Err(msg) => {
                        warn!("error getting latest block, skipping iteration: {msg:?}");
                        continue;
                    }
                },
                Err(_) => {
                    error!("get_latest_block_number() timed out on getting latest header");
                    continue;
                }
            };
            last_seen_block_counter += 1;
            if latest_block >= block_index {
                last_seen_block_counter = 0;
                info!("Discovered new blocks to gossip: {block_index}-{latest_block}");
            }
            // `..=` is the inclusive range operator, it includes the right side of the range.
            // Example: 1..=3 is equivalent to 1, 2, 3
            // Where as: 1..3 is equivalent to 1, 2
            // block_index will always contain the next block to be gossiped, so when we get a new
            // latest_block from `get_latest_block_number()` it will gossip all blocks
            // from block_index to latest_block.
            for height in block_index..=latest_block {
                self.metrics.report_current_block(height as i64);
                Self::spawn_serve_full_block(
                    height,
                    None,
                    self.gossip_tx.clone(),
                    self.execution_api.clone(),
                    self.metrics.clone(),
                );
            }
            block_index = latest_block + 1;
            // Ethereum mainnet creates a new block every 15 seconds, if we don't get a new block
            // within 1 minute. There is a problem with the provider so throw an error.
            if last_seen_block_counter > 60 / LATEST_BLOCK_POLL_RATE {
                tracing::error!("History Latest: Haven't received a new block in over 60 seconds. EL provider could be out of sync.");
            }
        }
    }

    async fn launch_backfill(&self) {
        let latest_block = self.execution_api.get_latest_block_number().await.expect(
            "Error launching bridge in backfill mode. Unable to get latest block from provider.",
        );
        let gossip_range = self
            .mode
            .get_block_range(latest_block)
            .expect("Error launching bridge in backfill mode: Invalid block range.");
        // initialize current_epoch_index as an impossible value u64::MAX so that
        // epoch_acc gets set on the first iteration of the loop
        let mut current_epoch_index = u64::MAX;

        info!("fetching headers in range: {gossip_range:?}");
        let mut epoch_acc = None;
        let mut serve_full_block_handles = vec![];
        for height in gossip_range {
            // Using epoch_size chunks & epoch boundaries ensures that every
            // "chunk" shares an epoch accumulator avoiding the need to
            // look up the epoch acc on a header by header basis
            if height <= MERGE_BLOCK_NUMBER && current_epoch_index != height / EPOCH_SIZE {
                current_epoch_index = height / EPOCH_SIZE;
                epoch_acc = match self
                    .construct_and_gossip_epoch_acc(current_epoch_index)
                    .await
                {
                    Ok(val) => Some(val),
                    Err(msg) => {
                        warn!("Unable to find epoch acc for gossip range: {current_epoch_index}. Skipping iteration: {msg:?}");
                        continue;
                    }
                };
            } else if height > MERGE_BLOCK_NUMBER {
                epoch_acc = None;
            }
            self.metrics.report_current_block(height as i64);
            serve_full_block_handles.push(Self::spawn_serve_full_block(
                height,
                epoch_acc.clone(),
                self.gossip_tx.clone(),
                self.execution_api.clone(),
                self.metrics.clone(),
            ));
        }

        // Wait till all blocks are done gossiping.
        // This can't deadlock, because the tokio::spawn has a timeout.
        join_all(serve_full_block_handles).await;
    }

    fn spawn_serve_full_block(
        height: u64,
        epoch_acc: Option<Arc<EpochAccumulator>>,
        gossip_tx: UnboundedSender<GossipRequest>,
        execution_api: ExecutionApi,
        metrics: BridgeMetricsReporter,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let timer = metrics.start_process_timer("spawn_serve_full_block");
            match timeout(
                SERVE_BLOCK_TIMEOUT,
                Self::serve_full_block(height, epoch_acc, gossip_tx, execution_api, metrics.clone())
                    .in_current_span(),
            )
            .await {
                Ok(result) => match result {
                    Ok(_) => debug!("Successfully served block: {height}"),
                    Err(msg) => warn!("Error serving block: {height}: {msg:?}"),
                },
                Err(_) => error!("serve_full_block() timed out on height {height}: this is an indication a bug is present")
            };
            metrics.stop_process_timer(timer);
        })
    }

    async fn serve_full_block(
        height: u64,
        epoch_acc: Option<Arc<EpochAccumulator>>,
        gossip_tx: UnboundedSender<GossipRequest>,
        execution_api: ExecutionApi,
        metrics: BridgeMetricsReporter,
    ) -> anyhow::Result<()> {
        info!("Serving block: {height}");
        let timer = metrics.start_process_timer("construct_and_gossip_header");
        let (full_header, header_content_key, header_content_value) =
            execution_api.get_header(height, epoch_acc).await?;
        debug!("Built and validated HeaderWithProof for Block #{height:?}: now gossiping.");
        let gossip_request =
            GossipRequest::from((header_content_key.clone(), header_content_value));
        if let Err(err) = gossip_tx.send(gossip_request) {
            bail!("Error sending HeaderWithProof gossip request to gossip engine: {err:?}");
        };
        metrics.stop_process_timer(timer);

        // Sleep for 10 seconds to allow headers to saturate network,
        // since they must be available for body / receipt validation.
        sleep(Duration::from_secs(HEADER_SATURATION_DELAY)).await;

        let block_body_full_header = full_header.clone();
        let block_body_execution_api = execution_api.clone();
        let block_body_metrics = metrics.clone();
        let gossip_tx_clone = gossip_tx.clone();
        let serve_block_body_task = tokio::spawn(async move {
            match timeout(
                SERVE_CONTENT_TIMEOUT,
                HistoryBridge::construct_and_gossip_block_body(
                    &block_body_full_header,
                    gossip_tx_clone,
                    &block_body_execution_api,
                    block_body_metrics,
                ).in_current_span(),
            )
            .await {
                Ok(result) => {
                    if let Err(msg) = result {
                        warn!("Error gossiping block body #{height:?}: {msg:?}");
                    }
                },
                Err(_) => error!("construct_and_gossip_block_body() timed out on height {height}: this is an indication a bug is present")
            };
        });
        let gossip_tx_clone = gossip_tx.clone();
        let serve_receipt_task = tokio::spawn(async move {
            match timeout(
                SERVE_CONTENT_TIMEOUT,
                HistoryBridge::construct_and_gossip_receipt(
                    &full_header,
                    gossip_tx_clone,
                    &execution_api,
                    metrics,
                ).in_current_span(),
            )
            .await {
                Ok(result) => match result {
                    Ok(_) => (),
                    Err(msg) => warn!("Error gossiping block receipt #{height:?}: {msg:?}"),
                },
                Err(_) => error!("construct_and_gossip_receipt() timed out on height {height}: this is an indication a bug is present")
            };
        });

        serve_block_body_task.await?;
        serve_receipt_task.await?;
        Ok(())
    }

    /// Attempt to lookup an epoch accumulator from local portal-accumulators path provided via cli
    /// arg. Gossip the epoch accumulator if found.
    async fn construct_and_gossip_epoch_acc(
        &self,
        epoch_index: u64,
    ) -> anyhow::Result<Arc<EpochAccumulator>> {
        let (epoch_hash, epoch_acc) = lookup_epoch_acc(
            epoch_index,
            &self.header_oracle.header_validator.pre_merge_acc,
            &self.epoch_acc_path,
        )
        .await?;
        // Gossip epoch acc to network if found locally
        let content_key = HistoryContentKey::EpochAccumulator(EpochAccumulatorKey { epoch_hash });
        let content_value = HistoryContentValue::EpochAccumulator(epoch_acc.clone());
        debug!("Built EpochAccumulator for Epoch #{epoch_index:?}: now gossiping.");
        let gossip_request = GossipRequest::from((content_key, content_value));
        if let Err(err) = self.gossip_tx.send(gossip_request) {
            bail!("Error sending EpochAccumulator gossip request to gossip engine: {err:?}");
        };
        Ok(Arc::new(epoch_acc))
    }

    async fn construct_and_gossip_receipt(
        full_header: &FullHeader,
        gossip_tx: UnboundedSender<GossipRequest>,
        execution_api: &ExecutionApi,
        metrics: BridgeMetricsReporter,
    ) -> anyhow::Result<()> {
        let timer = metrics.start_process_timer("construct_and_gossip_receipt");
        let (content_key, content_value) = execution_api.get_receipts(full_header).await?;
        debug!(
            "Built and validated Receipts for Block #{:?}: now gossiping.",
            full_header.header.number
        );
        let gossip_request = GossipRequest::from((content_key, content_value));
        if let Err(err) = gossip_tx.send(gossip_request) {
            bail!("Error sending Receipts gossip request to gossip engine: {err:?}");
        };
        metrics.stop_process_timer(timer);
        Ok(())
    }

    async fn construct_and_gossip_block_body(
        full_header: &FullHeader,
        gossip_tx: UnboundedSender<GossipRequest>,
        execution_api: &ExecutionApi,
        metrics: BridgeMetricsReporter,
    ) -> anyhow::Result<()> {
        let timer = metrics.start_process_timer("construct_and_gossip_block_body");
        let (content_key, content_value) = execution_api.get_block_body(full_header).await?;
        debug!(
            "Built and validated BlockBody for Block #{:?}: now gossiping.",
            full_header.header.number
        );
        let gossip_request = GossipRequest::from((content_key, content_value));
        if let Err(err) = gossip_tx.send(gossip_request) {
            bail!("Error sending BlockBody gossip request to gossip engine: {err:?}");
        };
        metrics.stop_process_timer(timer);
        Ok(())
    }
}
