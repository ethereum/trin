use crate::full_header::FullHeader;
use crate::mode::{BridgeMode, ModeType};
use crate::pandaops::PandaOpsMiddleware;
use crate::utils::TestAssets;
use anyhow::{anyhow, bail};
use ethportal_api::jsonrpsee::http_client::HttpClient;
use ethportal_api::types::execution::accumulator::EpochAccumulator;
use ethportal_api::types::execution::block_body::{
    BlockBody, BlockBodyLegacy, BlockBodyMerge, BlockBodyShanghai, MERGE_TIMESTAMP,
    SHANGHAI_TIMESTAMP,
};
use ethportal_api::types::execution::header::{
    AccumulatorProof, BlockHeaderProof, Header, HeaderWithProof, SszNone,
};
use ethportal_api::types::execution::receipts::Receipts;
use ethportal_api::utils::bytes::hex_encode;
use ethportal_api::HistoryContentValue;
use ethportal_api::HistoryNetworkApiClient;
use ethportal_api::{
    BlockBodyKey, BlockHeaderKey, BlockReceiptsKey, EpochAccumulatorKey, HistoryContentKey,
};
use futures::stream::StreamExt;
use ssz::Decode;
use std::fs;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time;
use surf::{
    middleware::{Middleware, Next},
    Body, Client, Request, Response,
};
use tokio::time::{sleep, Duration};
use tracing::{debug, info, warn};
use trin_validation::accumulator::MasterAccumulator;
use trin_validation::constants::{EPOCH_SIZE as EPOCH_SIZE_USIZE, MERGE_BLOCK_NUMBER};
use trin_validation::oracle::HeaderOracle;

// todo: calculate / test optimal saturation delay
const HEADER_SATURATION_DELAY: u64 = 10; // seconds
const LATEST_BLOCK_POLL_RATE: u64 = 5; // seconds
const EPOCH_SIZE: u64 = EPOCH_SIZE_USIZE as u64;
const FUTURES_BUFFER_SIZE: usize = 32;

pub struct Bridge {
    pub mode: BridgeMode,
    pub portal_clients: Vec<HttpClient>,
    pub pandaops: PandaOpsMiddleware,
    pub header_oracle: HeaderOracle,
    pub epoch_acc_path: PathBuf,
}

impl Bridge {
    pub fn new(
        mode: BridgeMode,
        portal_clients: Vec<HttpClient>,
        header_oracle: HeaderOracle,
        epoch_acc_path: PathBuf,
    ) -> Self {
        Self {
            mode,
            portal_clients,
            pandaops: PandaOpsMiddleware::default(),
            header_oracle,
            epoch_acc_path,
        }
    }
}

impl Bridge {
    pub async fn launch(&self) {
        info!("Launching bridge mode: {:?}", self.mode);
        match self.mode.clone() {
            BridgeMode::Test(path) => self.launch_test(path).await,
            BridgeMode::Latest => self.launch_latest().await,
            _ => self.launch_backfill().await,
        }
        info!("Bridge mode: {:?} complete.", self.mode);
    }

    async fn launch_test(&self, test_path: PathBuf) {
        let test_asset = fs::read_to_string(test_path).expect("Error reading test asset.");
        let assets: TestAssets =
            serde_json::from_str(&test_asset).expect("Unable to parse test asset.");
        for asset in assets.0.into_iter() {
            Bridge::gossip_content(&self.portal_clients, asset.content_key, asset.content_value)
                .await
                .expect("Error serving block range in test mode.");
        }
    }

    // Devops nodes don't have websockets available, so we can't actually poll the latest block.
    // Instead we loop on a short interval and fetch the latest blocks not yet served.
    async fn launch_latest(&self) {
        let mut block_index = self.pandaops.get_latest_block_number().await.expect(
            "Error launching bridge in latest mode. Unable to get latest block from provider.",
        );
        loop {
            sleep(Duration::from_secs(LATEST_BLOCK_POLL_RATE)).await;
            let latest_block = match self.pandaops.get_latest_block_number().await {
                Ok(val) => val,
                Err(msg) => {
                    warn!("error getting latest block, skipping iteration: {msg:?}");
                    continue;
                }
            };
            if latest_block > block_index {
                let gossip_range = Range {
                    start: block_index,
                    end: latest_block + 1,
                };
                info!("Discovered new blocks to gossip: {gossip_range:?}");
                let gossip_stats = Arc::new(Mutex::new(GossipStats::new(gossip_range.clone())));
                let epoch_acc = None;
                self.serve(gossip_range.clone(), epoch_acc, gossip_stats.clone())
                    .await
                    .expect("Error serving block range in latest mode.");
                block_index = gossip_range.end;
            }
        }
    }

    async fn launch_backfill(&self) {
        let latest_block = self.pandaops.get_latest_block_number().await.expect(
            "Error launching bridge in backfill mode. Unable to get latest block from provider.",
        );
        let (looped, mode_type) = match self.mode.clone() {
            BridgeMode::Backfill(val) => (true, val),
            BridgeMode::Single(val) => (false, val),
            _ => panic!("Invalid backfill mode"),
        };
        let (mut start_block, mut end_block, mut epoch_index) = match mode_type {
            // end block will be same for an epoch in single & backfill modes
            ModeType::Epoch(block) => (
                block * EPOCH_SIZE,
                ((block + 1) * EPOCH_SIZE),
                block / EPOCH_SIZE,
            ),
            ModeType::Block(block) => {
                let epoch_index = block / EPOCH_SIZE;
                let end_block = match looped {
                    true => (epoch_index + 1) * EPOCH_SIZE,
                    false => block + 1,
                };
                (block, end_block, epoch_index)
            }
        };
        if start_block > latest_block {
            panic!(
                "Starting block/epoch is greater than latest block. 
                        Please specify a starting block/epoch that begins before the current block."
            );
        }
        let current_epoch = latest_block / EPOCH_SIZE;
        let mut gossip_range = Range {
            start: start_block,
            end: end_block,
        };
        let gossip_stats = Arc::new(Mutex::new(GossipStats::new(gossip_range.clone())));
        while epoch_index < current_epoch {
            // Using epoch_size chunks & epoch boundaries ensures that every
            // "chunk" shares an epoch accumulator avoiding the need to
            // look up the epoch acc on a header by header basis
            let epoch_acc = if gossip_range.end <= MERGE_BLOCK_NUMBER {
                match self.get_epoch_acc(epoch_index).await {
                    Ok(val) => Some(val),
                    Err(msg) => {
                        warn!("Unable to find epoch acc for gossip range: {gossip_range:?}. Skipping iteration: {msg:?}");
                        continue;
                    }
                }
            } else {
                None
            };
            info!("fetching headers in range: {gossip_range:?}");
            self.serve(gossip_range, epoch_acc, gossip_stats.clone())
                .await
                .expect("Error serving headers in backfill mode.");
            if let Ok(gossip_stats) = gossip_stats.lock() {
                gossip_stats.display_stats();
            } else {
                warn!("Error displaying gossip stats. Unable to acquire lock.");
            }
            if !looped {
                break;
            }
            // update index values if we're looping
            epoch_index += 1;
            start_block = epoch_index * EPOCH_SIZE;
            end_block = start_block + EPOCH_SIZE;
            gossip_range = Range {
                start: start_block,
                end: end_block,
            };
        }
    }

    async fn serve(
        &self,
        gossip_range: Range<u64>,
        epoch_acc: Option<Arc<EpochAccumulator>>,
        gossip_stats: Arc<Mutex<GossipStats>>,
    ) -> anyhow::Result<()> {
        let futures = futures::stream::iter(gossip_range.into_iter().map(|height| {
            let epoch_acc = epoch_acc.clone();
            let gossip_stats = gossip_stats.clone();
            async move {
                let _ = self
                    .serve_full_block(height, epoch_acc, gossip_stats, self.portal_clients.clone())
                    .await;
            }
        }))
        .buffer_unordered(FUTURES_BUFFER_SIZE)
        .collect::<Vec<()>>();
        futures.await;
        if let Ok(gossip_stats) = gossip_stats.lock() {
            gossip_stats.display_stats();
        } else {
            warn!("Error displaying gossip stats. Unable to acquire lock.");
        }
        Ok(())
    }

    async fn serve_full_block(
        &self,
        height: u64,
        epoch_acc: Option<Arc<EpochAccumulator>>,
        gossip_stats: Arc<Mutex<GossipStats>>,
        portal_clients: Vec<HttpClient>,
    ) -> anyhow::Result<()> {
        debug!("Serving block: {height}");
        let mut full_header = self.pandaops.get_header(height).await?;
        if full_header.header.number <= MERGE_BLOCK_NUMBER {
            full_header.epoch_acc = epoch_acc;
        }
        Bridge::gossip_header(&full_header, &portal_clients, &gossip_stats).await?;
        // Sleep for 10 seconds to allow headers to saturate network,
        // since they must be available for body / receipt validation.
        sleep(Duration::from_secs(HEADER_SATURATION_DELAY)).await;
        self.construct_and_gossip_block_body(&full_header, &portal_clients, &gossip_stats)
            .await
            .map_err(|err| anyhow!("Error gossiping block body #{height:?}: {err:?}"))?;

        self.construct_and_gossip_receipt(&full_header, &portal_clients, &gossip_stats)
            .await
            .map_err(|err| anyhow!("Error gossiping receipt #{height:?}: {err:?}"))?;
        Ok(())
    }

    async fn gossip_header(
        full_header: &FullHeader,
        portal_clients: &Vec<HttpClient>,
        gossip_stats: &Arc<Mutex<GossipStats>>,
    ) -> anyhow::Result<()> {
        debug!("Serving header: {}", full_header.header.number);
        if full_header.header.number < MERGE_BLOCK_NUMBER && full_header.epoch_acc.is_none() {
            bail!("Invalid header, expected to have epoch accumulator");
        }
        let content_key = HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey {
            block_hash: full_header.header.hash().to_fixed_bytes(),
        });
        // validate pre-merge
        let content_value = match &full_header.epoch_acc {
            Some(epoch_acc) => {
                // Fetch HeaderRecord from EpochAccumulator for validation
                let header_index = full_header.header.number % EPOCH_SIZE;
                let header_record = &epoch_acc[header_index as usize];

                // Validate Header
                if header_record.block_hash != full_header.header.hash() {
                    bail!(
                        "Header hash doesn't match record in local accumulator: {:?} - {:?}",
                        full_header.header.hash(),
                        header_record.block_hash
                    );
                }
                // Construct HeaderWithProof
                let header_with_proof =
                    Bridge::construct_proof(full_header.header.clone(), epoch_acc).await?;
                HistoryContentValue::BlockHeaderWithProof(header_with_proof)
            }
            None => {
                let header_with_proof = HeaderWithProof {
                    header: full_header.header.clone(),
                    proof: BlockHeaderProof::None(SszNone { value: None }),
                };
                HistoryContentValue::BlockHeaderWithProof(header_with_proof)
            }
        };
        debug!(
            "Gossip: Block #{:?} HeaderWithProof",
            full_header.header.number
        );
        let result = Bridge::gossip_content(portal_clients, content_key, content_value).await;
        if result.is_ok() {
            if let Ok(mut data) = gossip_stats.lock() {
                data.header_with_proof_count += 1;
            } else {
                warn!("Error updating gossip header with proof stats. Unable to acquire lock.");
            }
        }
        result
    }

    /// Attempt to lookup an epoch accumulator from local portal-accumulators path provided via cli
    /// arg. Gossip the epoch accumulator if found.
    async fn get_epoch_acc(&self, epoch_index: u64) -> anyhow::Result<Arc<EpochAccumulator>> {
        let epoch_hash = self.header_oracle.master_acc.historical_epochs[epoch_index as usize];
        let epoch_hash_pretty = hex_encode(epoch_hash);
        let epoch_hash_pretty = epoch_hash_pretty.trim_start_matches("0x");
        let epoch_acc_path = format!(
            "{}/bridge_content/0x03{epoch_hash_pretty}.portalcontent",
            self.epoch_acc_path.display(),
        );
        let local_epoch_acc = match fs::read(&epoch_acc_path) {
            Ok(val) => EpochAccumulator::from_ssz_bytes(&val).map_err(|err| anyhow!("{err:?}"))?,
            Err(_) => {
                return Err(anyhow!(
                    "Unable to find local epoch acc at path: {epoch_acc_path:?}"
                ))
            }
        };
        // Gossip epoch acc to network if found locally
        let content_key = HistoryContentKey::EpochAccumulator(EpochAccumulatorKey { epoch_hash });
        let content_value = HistoryContentValue::EpochAccumulator(local_epoch_acc.clone());
        let _ = Bridge::gossip_content(&self.portal_clients, content_key, content_value).await;
        Ok(Arc::new(local_epoch_acc))
    }

    async fn construct_and_gossip_receipt(
        &self,
        full_header: &FullHeader,
        portal_clients: &Vec<HttpClient>,
        gossip_stats: &Arc<Mutex<GossipStats>>,
    ) -> anyhow::Result<()> {
        debug!("Serving receipt: {:?}", full_header.header.number);
        let receipts = match full_header.txs.len() {
            0 => Receipts {
                receipt_list: vec![],
            },
            _ => {
                self.pandaops
                    .get_trusted_receipts(&full_header.tx_hashes.hashes)
                    .await?
            }
        };

        // Validate Receipts
        let receipts_root = receipts.root()?;
        if receipts_root != full_header.header.receipts_root {
            bail!(
                "Receipts root doesn't match header receipts root: {receipts_root:?} - {:?}",
                full_header.header.receipts_root
            );
        }
        let content_key = HistoryContentKey::BlockReceipts(BlockReceiptsKey {
            block_hash: full_header.header.hash().to_fixed_bytes(),
        });
        let content_value = HistoryContentValue::Receipts(receipts);
        debug!("Gossip: Block #{:?} Receipts", full_header.header.number,);
        let result = Bridge::gossip_content(portal_clients, content_key, content_value).await;
        if result.is_ok() {
            if let Ok(mut data) = gossip_stats.lock() {
                data.receipts_count += 1;
            } else {
                warn!("Error updating gossip receipts stats. Unable to acquire lock.");
            }
        }
        result
    }

    async fn construct_and_gossip_block_body(
        &self,
        full_header: &FullHeader,
        portal_clients: &Vec<HttpClient>,
        gossip_stats: &Arc<Mutex<GossipStats>>,
    ) -> anyhow::Result<()> {
        let txs = full_header.txs.clone();
        let block_body = if full_header.header.timestamp > SHANGHAI_TIMESTAMP {
            if !full_header.uncles.is_empty() {
                bail!("Invalid block: Shanghai block contains uncles");
            }
            let withdrawals = match full_header.withdrawals.clone() {
                Some(val) => val,
                None => bail!("Invalid block: Shanghai block missing withdrawals"),
            };
            BlockBody::Shanghai(BlockBodyShanghai { txs, withdrawals })
        } else if full_header.header.timestamp > MERGE_TIMESTAMP {
            if !full_header.uncles.is_empty() {
                bail!("Invalid block: Merge block contains uncles");
            }
            BlockBody::Merge(BlockBodyMerge { txs })
        } else {
            let uncles = match full_header.uncles.len() {
                0 => vec![],
                _ => {
                    self.pandaops
                        .get_trusted_uncles(&full_header.uncles)
                        .await?
                }
            };
            BlockBody::Legacy(BlockBodyLegacy { txs, uncles })
        };
        block_body.validate_against_header(&full_header.header)?;

        let content_key = HistoryContentKey::BlockBody(BlockBodyKey {
            block_hash: full_header.header.hash().to_fixed_bytes(),
        });
        let content_value = HistoryContentValue::BlockBody(block_body);
        debug!("Gossip: Block #{:?} BlockBody", full_header.header.number);
        let result = Bridge::gossip_content(portal_clients, content_key, content_value).await;
        if result.is_ok() {
            if let Ok(mut data) = gossip_stats.lock() {
                data.bodies_count += 1;
            } else {
                warn!("Error updating gossip bodies stats. Unable to acquire lock.");
            }
        }
        result
    }

    /// Create a proof for the given header / epoch acc
    async fn construct_proof(
        header: Header,
        epoch_acc: &EpochAccumulator,
    ) -> anyhow::Result<HeaderWithProof> {
        let proof = MasterAccumulator::construct_proof(&header, epoch_acc)?;
        let proof = BlockHeaderProof::AccumulatorProof(AccumulatorProof { proof });
        Ok(HeaderWithProof { header, proof })
    }

    /// Gossip any given content key / value to the history network.
    async fn gossip_content(
        portal_clients: &Vec<HttpClient>,
        content_key: HistoryContentKey,
        content_value: HistoryContentValue,
    ) -> anyhow::Result<()> {
        for client in portal_clients {
            client
                .gossip(content_key.clone(), content_value.clone())
                .await?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct GossipStats {
    pub range: Range<u64>,
    pub header_with_proof_count: u64,
    pub bodies_count: u64,
    pub receipts_count: u64,
    pub start_time: time::Instant,
}

impl GossipStats {
    fn new(range: Range<u64>) -> Self {
        Self {
            range,
            header_with_proof_count: 0,
            bodies_count: 0,
            receipts_count: 0,
            start_time: time::Instant::now(),
        }
    }

    fn display_stats(&self) {
        info!(
            "Header Group: Range {:?} - Header with proof: {:?} - Bodies: {:?} - Receipts: {:?}",
            self.range, self.header_with_proof_count, self.bodies_count, self.receipts_count
        );
        info!("Group took: {:?}", time::Instant::now() - self.start_time);
    }
}

#[derive(Debug)]
pub struct Retry {
    attempts: u8,
}

impl Retry {
    pub fn new(attempts: u8) -> Self {
        Retry { attempts }
    }
}

#[async_trait::async_trait]
impl Middleware for Retry {
    async fn handle(
        &self,
        mut req: Request,
        client: Client,
        next: Next<'_>,
    ) -> Result<Response, surf::Error> {
        let mut retry_count: u8 = 0;
        let body = req.take_body().into_bytes().await?;
        while retry_count < self.attempts {
            if retry_count > 0 {
                info!("Retrying request");
            }
            let mut new_req = req.clone();
            new_req.set_body(Body::from_bytes(body.clone()));
            if let Ok(val) = next.run(new_req, client.clone()).await {
                if val.status().is_success() {
                    return Ok(val);
                }
            };
            retry_count += 1;
            sleep(Duration::from_millis(100)).await;
        }
        Err(surf::Error::from_str(
            500,
            "Unable to fetch batch after 3 retries",
        ))
    }
}

impl Default for Retry {
    fn default() -> Self {
        Self { attempts: 3 }
    }
}
