use std::env;
use std::fs;
use std::ops::Range;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::{thread, time};

use anyhow::anyhow;
use ethereum_types::H256;
use serde_json::{json, Value};
use ssz::{Decode, Encode};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::jsonrpc::endpoints::HistoryEndpoint;
use crate::jsonrpc::types::{HistoryJsonRpcRequest, JsonRequest, Params};
use crate::portalnet::types::content_key::{
    BlockBody as BlockBodyContentKey, BlockHeader, BlockReceipts, HistoryContentKey,
};
use crate::types::accumulator::{EpochAccumulator, MasterAccumulator, EPOCH_SIZE};
use crate::types::block_body::{BlockBody, EncodableHeaderList};
use crate::types::header::{
    AccumulatorProof, BlockHeaderProof, FullHeader, FullHeaderBatch, Header, HeaderWithProof,
};
use crate::types::receipts::Receipts;
use crate::types::validation::HeaderOracle;
use crate::types::validation::MERGE_BLOCK_NUMBER;
use crate::utils::bytes::hex_encode;

const BATCH_SIZE: u64 = 128;
const LATEST_BLOCK_POLL_RATE: u64 = 5;
const BACKFILL_THREAD_COUNT: usize = 8;

/// Bridge datatype is used to source history / state data from a geth node and offer it to other
/// nodes in the Portal network. Using bridge mode relies upon a separate provider than the
/// `TrustedProvider` used by Trin. These providers require access to nodes made available by the
/// EF devops team, and are not available for public use. For this reason, using bridge mode is
/// still considered "experimental" until it's updated to be compatible with any provider.
/// In the meantime, users can use the `ethportal-bridge` project to help feed data into the
/// Portal network.
/// https://github.com/carver/eth-portal
// todos / possible improvements
// - create docker image w/ epoch accs
// - offer epoch accumulators if available locally
// - latest xxx: cli arg to specify backfill of latest xxx blocks from head, then repeat
// - range xx-xxx: cli arg to specify specific range of blocks to backfill
// - backfill xx: cli arg to specifcy an epoch index from where to begin backfill
// - test against archive nodes...
// - test time / epoch against ethportal-bridge
pub struct Bridge {
    pub header_oracle: Arc<RwLock<HeaderOracle>>,
    pub epoch_acc_path: Option<PathBuf>,
    pub mode: BridgeMode,
}

impl Bridge {
    pub async fn launch(&self) {
        match self.mode {
            BridgeMode::Latest => self.launch_latest().await,
            BridgeMode::Backfill => self.launch_backfill().await,
        }
    }

    // Devops nodes don't have websockets available, so we can't actually poll the latest block.
    // Instead we loop on a short interval and fetch the latest blocks not yet served.
    // We only need one thread for this process
    async fn launch_latest(&self) {
        info!("Launching bridge mode: latest");
        let mut block_index = get_latest_block().await.unwrap();
        let sleep_duration = time::Duration::from_secs(LATEST_BLOCK_POLL_RATE);
        loop {
            let latest_block = match get_latest_block().await {
                Ok(val) => val,
                Err(msg) => {
                    warn!("error getting latest block, skipping iteration: {:?}", msg);
                    thread::sleep(sleep_duration);
                    continue;
                }
            };
            if latest_block > block_index {
                let blocks_to_serve = Range {
                    start: block_index,
                    end: latest_block + 1,
                };
                info!("Discovered new blocks to offer: {:?}", blocks_to_serve);
                let full_headers = match Bridge::get_headers(&blocks_to_serve).await {
                    Ok(val) => val,
                    Err(msg) => {
                        warn!("error getting headers: {:?}", msg);
                        block_index = latest_block + 1;
                        thread::sleep(sleep_duration);
                        continue;
                    }
                };
                // epoch index is 0 here bc it's irrelevant for post-merge headers
                let mut offer_group = OfferGroup::new(blocks_to_serve, 0);
                if let Err(msg) = self.offer_headers(&full_headers, &mut offer_group).await {
                    warn!("error offering blocks: {:?}", msg);
                    block_index = latest_block + 1;
                    thread::sleep(sleep_duration);
                    continue;
                };
                self.serve_bodies(&full_headers, &mut offer_group).await;
                self.serve_receipts(&full_headers, &mut offer_group).await;
                offer_group.display_stats();
                block_index = offer_group.range.end;
            }
            thread::sleep(sleep_duration);
        }
    }

    async fn launch_backfill(&self) {
        info!("Launching bridge mode: backfill");
        let mut epoch_index = 0;
        let latest_block = get_latest_block().await.unwrap();
        let current_epoch = latest_block / EPOCH_SIZE as u64;
        while epoch_index < current_epoch {
            let start_block = epoch_index * EPOCH_SIZE as u64;
            // Using epoch_size chunks & epoch boundaries ensures that every
            // "chunk" shares an epoch accumulator avoiding the need to
            // look up the epoch acc on a header by header basis
            let blocks_to_serve = Range {
                start: start_block,
                end: start_block + EPOCH_SIZE as u64,
            };
            let full_headers = match Bridge::get_headers(&blocks_to_serve).await {
                Ok(val) => val,
                Err(msg) => {
                    warn!(
                        "Error fetching headers in range: {:?} - {:?}",
                        blocks_to_serve, msg
                    );
                    epoch_index += 1;
                    continue;
                }
            };
            let mut offer_group = OfferGroup::new(blocks_to_serve.clone(), epoch_index);
            if let Err(msg) = self.offer_headers(&full_headers, &mut offer_group).await {
                warn!(
                    "Error offering headers in range: {:?} - {:?}",
                    blocks_to_serve, msg
                );
                epoch_index += 1;
                continue;
            };
            self.serve_bodies(&full_headers, &mut offer_group).await;
            self.serve_receipts(&full_headers, &mut offer_group).await;
            offer_group.display_stats();
            epoch_index += 1;
        }
    }

    /// Fetch batch of headers from Provider
    async fn get_headers(range: &Range<u64>) -> anyhow::Result<Vec<FullHeader>> {
        let mut headers: Vec<FullHeader> = vec![];
        let ranges = get_ranges(range);
        for range_set in ranges.chunks(BACKFILL_THREAD_COUNT) {
            let futures: Vec<JoinHandle<anyhow::Result<Vec<FullHeader>>>> = (0..range_set.len())
                .into_iter()
                .map(|t| Bridge::get_header_future(range_set[t].clone()))
                .collect();
            let mut results = Vec::with_capacity(futures.len());
            for future in futures {
                results.push(future.await?);
            }
            for result in results {
                for h in result? {
                    headers.push(h);
                }
            }
        }
        Ok(headers)
    }

    fn get_header_future(block_range: Range<u64>) -> JoinHandle<anyhow::Result<Vec<FullHeader>>> {
        tokio::spawn(async move {
            debug!("Fetching headers: {:?}", block_range);
            let request_batch: Vec<JsonRequest> = block_range
                .into_iter()
                .map(|i| {
                    // Geth requires block numbers to be formatted using the following padding.
                    let block_param = format!("0x{:01X}", i);
                    let params = Params::Array(vec![json!(block_param), json!(true)]);
                    json_request("eth_getBlockByNumber".to_string(), params, i as u32)
                })
                .collect();
            let response = geth_batch_request(request_batch).await?;
            let batch: FullHeaderBatch = serde_json::from_str(&response)?;
            Ok(batch.headers)
        })
    }

    async fn offer_headers(
        &self,
        full_headers: &Vec<FullHeader>,
        offer_group: &mut OfferGroup,
    ) -> anyhow::Result<()> {
        info!("Offering headers in range: {:?}", offer_group.range);
        if offer_group.range.end <= MERGE_BLOCK_NUMBER {
            self.offer_premerge_headers(full_headers, offer_group).await
        } else {
            self.offer_postmerge_headers(full_headers, offer_group)
                .await
        }
    }

    async fn offer_premerge_headers(
        &self,
        full_headers: &Vec<FullHeader>,
        offer_group: &mut OfferGroup,
    ) -> anyhow::Result<()> {
        let tx = self.history_tx().await;
        let epoch_index = offer_group.epoch_index;
        let epoch_acc = self.get_epoch_acc(epoch_index).await?;
        for full_header in full_headers {
            let content_key = HistoryContentKey::BlockHeader(BlockHeader {
                block_hash: full_header.header.hash().to_fixed_bytes(),
            });
            let content_key: Vec<u8> = content_key.into();
            let content_value = rlp::encode(&full_header.header);

            // Fetch HeaderRecord from EpochAccumulator for validation
            let header_index =
                (full_header.header.number as u64) - epoch_index * (EPOCH_SIZE as u64);
            let header_record = &epoch_acc[header_index as usize];

            // Validate Header
            if header_record.block_hash != full_header.header.hash() {
                return Err(anyhow!(
                    "Header hash doesn't match record in local accumulator: {:?} - {:?}",
                    full_header.header.hash(),
                    header_record.block_hash
                ));
            }

            // Offer Header
            debug!("Offer: Block #{:?} Header", full_header.header.number);
            if Bridge::offer_content(
                tx.clone(),
                hex_encode(content_key),
                hex_encode(content_value),
            )
            .await
            .is_ok()
            {
                offer_group.header_count += 1;
            }

            // Construct HeaderWithProof
            let (content_key, hwp) = self
                .construct_proof(&full_header.header, &epoch_acc)
                .await?;
            let content_key: Vec<u8> = content_key.into();
            debug!(
                "Offer: Block #{:?} HeaderWithProof",
                full_header.header.number
            );

            // Offer HeaderWithProof
            if Bridge::offer_content(
                tx.clone(),
                hex_encode(content_key),
                hex_encode(hwp.as_ssz_bytes()),
            )
            .await
            .is_ok()
            {
                offer_group.hwp_count += 1;
            }
        }
        Ok(())
    }

    async fn offer_postmerge_headers(
        &self,
        full_headers: &Vec<FullHeader>,
        offer_group: &mut OfferGroup,
    ) -> anyhow::Result<()> {
        for full_header in full_headers {
            let content_key = HistoryContentKey::BlockHeader(BlockHeader {
                block_hash: full_header.header.hash().to_fixed_bytes(),
            });
            let content_key: Vec<u8> = content_key.into();
            let content_value = rlp::encode(&full_header.header);
            let tx = self.history_tx().await;
            debug!("Offer: Block #{:?} Header", full_header.header.number);
            if Bridge::offer_content(tx, hex_encode(content_key), hex_encode(content_value))
                .await
                .is_ok()
            {
                offer_group.header_count += 1;
            }
        }
        Ok(())
    }

    /// Attempt to lookup an epoch accumulator from local portal-accumulators path provided via cli
    /// arg. Fallback to retrieving epoch acc from network if unable to find epoch acc locally.
    async fn get_epoch_acc(&self, epoch_index: u64) -> anyhow::Result<EpochAccumulator> {
        let epoch_hash =
            self.header_oracle.read().await.master_acc.historical_epochs[epoch_index as usize];
        let local_epoch_acc = match &self.epoch_acc_path {
            Some(val) => {
                let epoch_hash_pretty = hex_encode(epoch_hash);
                let epoch_hash_pretty = epoch_hash_pretty.trim_start_matches("0x");
                let epoch_acc_path = format!(
                    "{}/bridge_content/0x03{}.portalcontent",
                    val.display(),
                    epoch_hash_pretty
                );
                match fs::read(epoch_acc_path) {
                    Ok(val) => Some(
                        EpochAccumulator::from_ssz_bytes(&val)
                            .map_err(|err| anyhow!("{:?}", err))?,
                    ),
                    Err(_) => None,
                }
            }
            None => None,
        };
        match local_epoch_acc {
            Some(val) => Ok(val),
            None => {
                let tx = self.history_tx().await;
                self.header_oracle
                    .read()
                    .await
                    .master_acc
                    .lookup_epoch_acc(epoch_hash, tx)
                    .await
            }
        }
    }

    /// Fetch batch of BlockBodies from provider & offer them to the network
    /// Spawns the futures in groups of size - BACKFILL_THREAD_COUNT
    async fn serve_bodies(&self, full_headers: &Vec<FullHeader>, offer_group: &mut OfferGroup) {
        info!("Serving bodies in range: {:?}", offer_group.range);
        let tx = self.history_tx().await;
        let mut header_index = 0;
        while header_index < full_headers.len() {
            let num_of_tasks =
                std::cmp::min(BACKFILL_THREAD_COUNT, full_headers.len() - header_index);
            let futures: Vec<JoinHandle<anyhow::Result<()>>> = (0..num_of_tasks)
                .into_iter()
                .map(|t| {
                    Bridge::spawn_body_task(tx.clone(), full_headers[header_index + t].clone())
                })
                .collect();
            for future in futures {
                if let Ok(Ok(_)) = future.await {
                    offer_group.bodies_count += 1;
                }
            }
            header_index += num_of_tasks;
        }
    }

    fn spawn_body_task(
        tx: UnboundedSender<HistoryJsonRpcRequest>,
        full_header: FullHeader,
    ) -> JoinHandle<anyhow::Result<()>> {
        tokio::spawn(async move { Bridge::construct_and_offer_block_body(tx, full_header).await })
    }

    /// Fetch batch of Receipts from provider & offer them to the network
    /// Spawns the futures in groups of size - BACKFILL_THREAD_COUNT
    async fn serve_receipts(&self, full_headers: &Vec<FullHeader>, offer_group: &mut OfferGroup) {
        info!("Serving receipts in range: {:?}", offer_group.range);
        let tx = self.history_tx().await;
        let mut header_index = 0;
        while header_index < full_headers.len() {
            let num_of_tasks =
                std::cmp::min(BACKFILL_THREAD_COUNT, full_headers.len() - header_index);
            let futures: Vec<JoinHandle<anyhow::Result<()>>> = (0..num_of_tasks)
                .into_iter()
                .map(|t| {
                    Bridge::spawn_receipt_task(tx.clone(), full_headers[header_index + t].clone())
                })
                .collect();
            for future in futures {
                if let Ok(Ok(_)) = future.await {
                    offer_group.receipts_count += 1;
                }
            }
            header_index += num_of_tasks;
        }
    }

    fn spawn_receipt_task(
        tx: UnboundedSender<HistoryJsonRpcRequest>,
        full_header: FullHeader,
    ) -> JoinHandle<anyhow::Result<()>> {
        tokio::spawn(async move { Bridge::construct_and_offer_receipt(tx, full_header).await })
    }

    async fn construct_and_offer_receipt(
        tx: UnboundedSender<HistoryJsonRpcRequest>,
        full_header: FullHeader,
    ) -> anyhow::Result<()> {
        let receipts = match full_header.txs.len() {
            0 => Receipts {
                receipt_list: vec![],
            },
            _ => Bridge::get_receipts_batch(full_header.tx_hashes.hashes).await?,
        };

        // Validate Receipts
        let receipts_root = receipts.root()?;
        if receipts_root != full_header.header.receipts_root {
            return Err(anyhow!(
                "Receipts root doesn't match header receipts root: {:?} - {:?}",
                receipts_root,
                full_header.header.receipts_root
            ));
        }

        let content_key = HistoryContentKey::BlockReceipts(BlockReceipts {
            block_hash: full_header.header.hash().to_fixed_bytes(),
        });
        let content_key: Vec<u8> = content_key.into();
        debug!(
            "Offer: Block #{:?} Receipts: len: {:?}",
            full_header.header.number,
            receipts.receipt_list.len()
        );
        Bridge::offer_content(
            tx,
            hex_encode(content_key),
            hex_encode(receipts.as_ssz_bytes()),
        )
        .await
    }

    async fn get_receipts_batch(tx_hashes: Vec<H256>) -> anyhow::Result<Receipts> {
        let request: Vec<JsonRequest> = tx_hashes
            .iter()
            .enumerate()
            .map(|(id, tx_hash)| {
                let tx_hash = hex_encode(tx_hash);
                let params = Params::Array(vec![json!(tx_hash)]);
                let method = "eth_getTransactionReceipt".to_string();
                json_request(method, params, id as u32)
            })
            .collect();
        let response = geth_batch_request(request).await?;
        Ok(serde_json::from_str(&response)?)
    }

    async fn construct_and_offer_block_body(
        tx: UnboundedSender<HistoryJsonRpcRequest>,
        full_header: FullHeader,
    ) -> anyhow::Result<()> {
        let uncle_headers = match full_header.uncles.len() {
            0 => vec![],
            _ => Bridge::get_uncles_batch(full_header.uncles).await?,
        };

        let block_body = BlockBody {
            txs: full_header.txs,
            uncles: EncodableHeaderList {
                list: uncle_headers,
            },
        };
        // Validate uncles root
        let uncles_root = block_body.uncles_root()?;
        if uncles_root != full_header.header.uncles_hash {
            return Err(anyhow!(
                "Block body uncles root doesn't match header uncles root: {:?} - {:?}",
                uncles_root,
                full_header.header.uncles_hash
            ));
        }
        // Validate txs root
        let txs_root = block_body.transactions_root()?;
        if txs_root != full_header.header.transactions_root {
            return Err(anyhow!(
                "Block body txs root doesn't match header txs root: {:?} - {:?}",
                txs_root,
                full_header.header.transactions_root
            ));
        }

        let content_key = HistoryContentKey::BlockBody(BlockBodyContentKey {
            block_hash: full_header.header.hash().to_fixed_bytes(),
        });
        let content_key: Vec<u8> = content_key.into();
        debug!("Offer: Block #{:?} BlockBody", full_header.header.number);
        Bridge::offer_content(
            tx,
            hex_encode(content_key),
            hex_encode(block_body.as_ssz_bytes()),
        )
        .await
    }

    async fn get_uncles_batch(hashes: Vec<H256>) -> anyhow::Result<Vec<Header>> {
        let request_batch = hashes
            .iter()
            .enumerate()
            .map(|(id, uncle)| {
                let uncle_hash = hex_encode(uncle);
                let params = Params::Array(vec![json!(uncle_hash), json!(false)]);
                let method = "eth_getBlockByHash".to_string();
                json_request(method, params, id as u32)
            })
            .collect();
        let response = geth_batch_request(request_batch).await?;
        let response: Vec<Value> = serde_json::from_str(&response).map_err(|e| anyhow!(e))?;
        // single responses are in an array, since we batch them...
        let mut headers = vec![];
        for res in response {
            if res["result"].as_object().is_none() {
                return Err(anyhow!("unable to find uncle header"));
            }
            let header: Header = serde_json::from_value(res.clone())?;
            headers.push(header)
        }
        Ok(headers)
    }

    /// Create a proof for the given header / epoch acc
    async fn construct_proof(
        &self,
        header: &Header,
        epoch_acc: &EpochAccumulator,
    ) -> anyhow::Result<(HistoryContentKey, HeaderWithProof)> {
        let proof = MasterAccumulator::construct_proof(header, epoch_acc)?;
        let proof = BlockHeaderProof::AccumulatorProof(AccumulatorProof { proof });
        let hwp = HeaderWithProof {
            header: header.clone(),
            proof,
        };
        let content_key = HistoryContentKey::BlockHeaderWithProof(BlockHeader {
            block_hash: header.hash().to_fixed_bytes(),
        });
        Ok((content_key, hwp))
    }

    /// Offer any given content key / value to the history network.
    async fn offer_content(
        tx: UnboundedSender<HistoryJsonRpcRequest>,
        content_key: String,
        content_value: String,
    ) -> anyhow::Result<()> {
        let params = Params::Array(vec![json!(content_key), json!(content_value)]);
        let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
        let json_request = HistoryJsonRpcRequest {
            endpoint: HistoryEndpoint::Offer,
            params,
            resp: resp_tx,
        };
        let _ = tx.send(json_request);

        match resp_rx.recv().await {
            Some(val) => match val {
                Ok(_) => Ok(()),
                Err(_) => Err(anyhow!("Invalid offer")),
            },
            None => Err(anyhow!("Invalid offer")),
        }
    }

    /// Fetch a cloned tx channel to history subnetwork
    async fn history_tx(&self) -> UnboundedSender<HistoryJsonRpcRequest> {
        self.header_oracle
            .read()
            .await
            .history_jsonrpc_tx()
            .unwrap()
    }
}

/// Used to help decode cli args identifying the desired bridge mode.
/// - Latest: tracks the latest header
/// - Backfill: starts at block 0
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BridgeMode {
    Latest,
    Backfill,
}

type ParseError = &'static str;

impl FromStr for BridgeMode {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "latest" => Ok(BridgeMode::Latest),
            "backfill" => Ok(BridgeMode::Backfill),
            _ => panic!("Invalid bridge mode arg: {s} is not an option."),
        }
    }
}

/// Datatype to help track & report stats for bridge
struct OfferGroup {
    range: Range<u64>,
    epoch_index: u64,
    header_count: u64,
    hwp_count: u64,
    bodies_count: u64,
    receipts_count: u64,
    start_time: time::Instant,
}

impl OfferGroup {
    fn new(range: Range<u64>, epoch_index: u64) -> Self {
        Self {
            range,
            epoch_index,
            header_count: 0,
            hwp_count: 0,
            bodies_count: 0,
            receipts_count: 0,
            start_time: time::Instant::now(),
        }
    }

    fn display_stats(&self) {
        info!(
            "Header Group: Range {:?} - Headers: {:?} - HWP: {:?} - Bodies: {:?} - Receipts: {:?}",
            self.range, self.header_count, self.hwp_count, self.bodies_count, self.receipts_count
        );
        info!("Group took: {:?}", time::Instant::now() - self.start_time);
    }
}

/// Used the "surf" library here instead of "ureq" since "surf" is much more capable of handling
/// multiple async requests. Using "ureq" consistently resulted in errors as soon as the number of
/// concurrent tasks increased significantly.
async fn geth_batch_request(obj: Vec<JsonRequest>) -> anyhow::Result<String> {
    let client_id =
        env::var("GETH_CLIENT_ID").map_err(|_| anyhow!("GETH_CLIENT_ID env var not set."))?;
    let client_secret = env::var("GETH_CLIENT_SECRET")
        .map_err(|_| anyhow!("GETH_CLIENT_SECRET env var not set."))?;

    let result = surf::post("https://geth-lighthouse.mainnet.ethpandaops.io/")
        .body_json(&json!(obj))
        .unwrap()
        .header("Content-Type", "application/json".to_string())
        .header("CF-Access-Client-Id", client_id)
        .header("CF-Access-Client-Secret", client_secret)
        .recv_string()
        .await;
    result.map_err(|_| anyhow!("xx"))
}

fn json_request(method: String, params: Params, id: u32) -> JsonRequest {
    JsonRequest {
        jsonrpc: "2.0".to_string(),
        params,
        method,
        id,
    }
}

async fn get_latest_block() -> anyhow::Result<u64> {
    let params = Params::Array(vec![json!("latest"), json!(false)]);
    let method = "eth_getBlockByNumber".to_string();
    let request = json_request(method, params, 1);
    let response = geth_batch_request(vec![request]).await?;
    let response: Vec<Value> = serde_json::from_str(&response)?;
    let result = response[0]
        .get("result")
        .ok_or_else(|| anyhow!("Unable to fetch latest block"))?;
    let header: Header = serde_json::from_value(result.clone())?;
    Ok(header.number)
}

/// Splits a range into chunks of (at most) BATCH_SIZE,
/// Used in "latest" mode, since most "chunks" will contain only a couple headers
fn get_ranges(range: &Range<u64>) -> Vec<Range<u64>> {
    let mut ranges = vec![];
    let mut index = range.start;
    while index < range.end {
        let end = std::cmp::min(index + BATCH_SIZE, range.end);
        let range = Range { start: index, end };
        ranges.push(range);
        index += BATCH_SIZE;
    }
    ranges
}
