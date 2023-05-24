use crate::cli::BridgeMode;
use crate::full_header::{FullHeader, FullHeaderBatch};
use anyhow::{anyhow, bail};
use ethereum_types::H256;
use ethportal_api::jsonrpsee::http_client::HttpClient;
use ethportal_api::types::consensus::withdrawal::Withdrawal;
use ethportal_api::types::content_key::{
    BlockBodyKey, BlockHeaderKey, BlockReceiptsKey, EpochAccumulatorKey, HistoryContentKey,
};
use ethportal_api::types::content_value::HistoryContentValue;
use ethportal_api::types::execution::accumulator::EpochAccumulator;
use ethportal_api::types::execution::block_body::{
    BlockBody, BlockBodyLegacy, BlockBodyMerge, BlockBodyShanghai, MERGE_TIMESTAMP,
    SHANGHAI_TIMESTAMP,
};
use ethportal_api::types::execution::header::{
    AccumulatorProof, BlockHeaderProof, Header, HeaderWithProof, SszNone,
};
use ethportal_api::types::execution::receipts::Receipts;
use ethportal_api::types::jsonrpc::params::Params;
use ethportal_api::types::jsonrpc::request::JsonRequest;
use ethportal_api::types::provider::{json_request, TrustedProvider};
use ethportal_api::utils::bytes::hex_encode;
use ethportal_api::HistoryNetworkApiClient;
use futures::stream::StreamExt;
use serde_json::{json, Value};
use ssz::Decode;
use std::fs;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time;
use tokio::time::{sleep, Duration};
use tracing::{debug, info, warn};
use trin_validation::accumulator::MasterAccumulator;
use trin_validation::constants::{EPOCH_SIZE as EPOCH_SIZE_USIZE, MERGE_BLOCK_NUMBER};
use trin_validation::oracle::HeaderOracle;

pub struct Bridge {
    pub mode: BridgeMode,
    pub portal_clients: Vec<HttpClient>,
    pub trusted_provider: TrustedProvider,
    pub header_oracle: HeaderOracle,
    pub epoch_acc_path: PathBuf,
}

// todo: calculate / test optimal saturation delay
// todo: single block option
const HEADER_SATURATION_DELAY: u64 = 10; // seconds
const LATEST_BLOCK_POLL_RATE: u64 = 5; // seconds
const EPOCH_SIZE: u64 = EPOCH_SIZE_USIZE as u64;
const FUTURES_BUFFER_SIZE: usize = 32;

impl Bridge {
    // Devops nodes don't have websockets available, so we can't actually poll the latest block.
    // Instead we loop on a short interval and fetch the latest blocks not yet served.
    pub async fn launch_latest(&self) {
        let mut block_index = self.get_latest_block_number().await.expect(
            "Error launching bridge in latest mode. Unable to get latest block from provider.",
        );
        loop {
            sleep(Duration::from_secs(LATEST_BLOCK_POLL_RATE)).await;
            let latest_block = match self.get_latest_block_number().await {
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
                let futures = futures::stream::iter(gossip_range.clone().map(|height| {
                    let gossip_stats = gossip_stats.clone();
                    async move {
                        let _ = Bridge::serve_full_block(
                            height,
                            None,
                            gossip_stats,
                            self.portal_clients.clone(),
                            self.trusted_provider.clone(),
                        )
                        .await;
                    }
                }))
                .buffer_unordered(FUTURES_BUFFER_SIZE)
                .collect::<Vec<()>>();
                futures.await;
                block_index = gossip_range.end;
            }
        }
    }

    pub async fn launch_backfill(&self, starting_epoch: Option<u64>) {
        let latest_block = self.get_latest_block_number().await.expect(
            "Error launching bridge in backfill mode. Unable to get latest block from provider.",
        );
        let mut epoch_index = match starting_epoch {
            Some(val) => {
                if val * EPOCH_SIZE > latest_block {
                    panic!(
                        "Starting epoch is greater than current epoch. 
                        Please specify a starting epoch that begins before the current block."
                    );
                }
                val
            }
            None => 0,
        };
        let current_epoch = latest_block / EPOCH_SIZE;
        while epoch_index < current_epoch {
            let start = epoch_index * EPOCH_SIZE;
            let end = start + EPOCH_SIZE;
            let gossip_range = Range { start, end };

            // Using epoch_size chunks & epoch boundaries ensures that every
            // "chunk" shares an epoch accumulator avoiding the need to
            // look up the epoch acc on a header by header basis
            let epoch_acc = if end <= MERGE_BLOCK_NUMBER {
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
            let gossip_stats = Arc::new(Mutex::new(GossipStats::new(gossip_range.clone())));
            let futures = futures::stream::iter(gossip_range.into_iter().map(|height| {
                let epoch_acc = epoch_acc.clone();
                let gossip_stats = gossip_stats.clone();
                async move {
                    let _ = Bridge::serve_full_block(
                        height,
                        epoch_acc,
                        gossip_stats,
                        self.portal_clients.clone(),
                        self.trusted_provider.clone(),
                    )
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
            epoch_index += 1;
        }
    }

    async fn get_latest_block_number(&self) -> anyhow::Result<u64> {
        let params = Params::Array(vec![json!("latest"), json!(false)]);
        let method = "eth_getBlockByNumber".to_string();
        let request = json_request(method, params, 1);
        let response = self
            .trusted_provider
            .clone()
            .batch_request(vec![request])
            .await?;
        let response: Vec<Value> = serde_json::from_str(&response)?;
        let result = response[0]
            .get("result")
            .ok_or_else(|| anyhow!("Unable to fetch latest block"))?;
        let header: Header = serde_json::from_value(result.clone())?;
        Ok(header.number)
    }

    async fn serve_full_block(
        height: u64,
        epoch_acc: Option<Arc<EpochAccumulator>>,
        gossip_stats: Arc<Mutex<GossipStats>>,
        portal_clients: Vec<HttpClient>,
        trusted_provider: TrustedProvider,
    ) -> anyhow::Result<()> {
        debug!("Serving block: {height}");
        let mut full_header = Bridge::get_header(height, trusted_provider.clone()).await?;
        if full_header.header.number <= MERGE_BLOCK_NUMBER {
            full_header.epoch_acc = epoch_acc;
        }
        Bridge::gossip_header(&full_header, &portal_clients, &gossip_stats).await?;
        // Sleep for 10 seconds to allow headers to saturate network,
        // since they must be available for body / receipt validation.
        sleep(Duration::from_secs(HEADER_SATURATION_DELAY)).await;
        Bridge::construct_and_gossip_block_body(
            &full_header,
            &portal_clients,
            &gossip_stats,
            trusted_provider.clone(),
        )
        .await?;
        Bridge::construct_and_gossip_receipt(
            &full_header,
            &portal_clients,
            &gossip_stats,
            trusted_provider,
        )
        .await
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
        full_header: &FullHeader,
        portal_clients: &Vec<HttpClient>,
        gossip_stats: &Arc<Mutex<GossipStats>>,
        trusted_provider: TrustedProvider,
    ) -> anyhow::Result<()> {
        debug!("Serving receipt: {:?}", full_header.header.number);
        let receipts = match full_header.txs.len() {
            0 => Receipts {
                receipt_list: vec![],
            },
            _ => {
                Bridge::get_trusted_receipts(&full_header.tx_hashes.hashes, trusted_provider)
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

    async fn get_trusted_receipts(
        tx_hashes: &[H256],
        trusted_provider: TrustedProvider,
    ) -> anyhow::Result<Receipts> {
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
        let response = trusted_provider.batch_request(request).await?;
        Ok(serde_json::from_str(&response)?)
    }

    async fn construct_and_gossip_block_body(
        full_header: &FullHeader,
        portal_clients: &Vec<HttpClient>,
        gossip_stats: &Arc<Mutex<GossipStats>>,
        trusted_provider: TrustedProvider,
    ) -> anyhow::Result<()> {
        let txs = full_header.txs.clone();
        let block_body = if full_header.header.timestamp > SHANGHAI_TIMESTAMP {
            if !full_header.uncles.is_empty() {
                bail!("Invalid block: Shanghai block contains uncles");
            }
            let withdrawals = Bridge::get_trusted_withdrawals(
                full_header.header.hash(),
                trusted_provider.clone(),
            )
            .await?;
            BlockBody::Shanghai(BlockBodyShanghai { txs, withdrawals })
        } else if full_header.header.timestamp > MERGE_TIMESTAMP {
            if !full_header.uncles.is_empty() {
                bail!("Invalid block: Merge block contains uncles");
            }
            BlockBody::Merge(BlockBodyMerge { txs })
        } else {
            let uncles = match full_header.uncles.len() {
                0 => vec![],
                _ => Bridge::get_trusted_uncles(&full_header.uncles, trusted_provider).await?,
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

    async fn get_trusted_uncles(
        hashes: &[H256],
        trusted_provider: TrustedProvider,
    ) -> anyhow::Result<Vec<Header>> {
        let batch_request = hashes
            .iter()
            .enumerate()
            .map(|(id, uncle)| {
                let uncle_hash = hex_encode(uncle);
                let params = Params::Array(vec![json!(uncle_hash), json!(false)]);
                let method = "eth_getBlockByHash".to_string();
                json_request(method, params, id as u32)
            })
            .collect();
        let response = trusted_provider.batch_request(batch_request).await?;
        let response: Vec<Value> = serde_json::from_str(&response).map_err(|e| anyhow!(e))?;
        // single responses are in an array, since we batch them...
        let mut headers = vec![];
        for res in response {
            if res["result"].as_object().is_none() {
                bail!("unable to find uncle header");
            }
            let header: Header = serde_json::from_value(res.clone())?;
            headers.push(header)
        }
        Ok(headers)
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

    async fn get_header(
        height: u64,
        trusted_provider: TrustedProvider,
    ) -> anyhow::Result<FullHeader> {
        // Geth requires block numbers to be formatted using the following padding.
        let block_param = format!("0x{height:01X}");
        let params = Params::Array(vec![json!(block_param), json!(true)]);
        let batch_request = vec![json_request(
            "eth_getBlockByNumber".to_string(),
            params,
            height as u32,
        )];
        let response = trusted_provider.batch_request(batch_request).await?;
        let batch: FullHeaderBatch = serde_json::from_str(&response)?;
        if batch.headers.len() != 1 {
            bail!("Expected 1 header, got {:#?}", batch.headers.len());
        }
        Ok(batch.headers[0].clone())
    }

    async fn get_trusted_withdrawals(
        block_hash: H256,
        trusted_provider: TrustedProvider,
    ) -> anyhow::Result<Vec<Withdrawal>> {
        let endpoint = format!("eth/v2/beacon/blocks/{}", hex_encode(block_hash));
        let response = trusted_provider.beacon_request(endpoint).await?;
        let result: Value = serde_json::from_str(&response)?;
        let withdrawals = result["data"]["body"]["withdrawals"].clone();
        Ok(serde_json::from_value(withdrawals)?)
    }
}

struct GossipStats {
    range: Range<u64>,
    header_with_proof_count: u64,
    bodies_count: u64,
    receipts_count: u64,
    start_time: time::Instant,
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
