use std::sync::Arc;

use alloy_primitives::B256;
use anyhow::{anyhow, bail};
use futures::future::join_all;
use serde_json::{json, Value};
use surf::Client;
use tokio::time::sleep;
use tracing::{debug, error, warn};

use crate::{constants::FALLBACK_RETRY_AFTER, types::full_header::FullHeader};
use ethportal_api::{
    types::{
        execution::{
            accumulator::EpochAccumulator,
            block_body::{
                BlockBody, BlockBodyLegacy, BlockBodyMerge, BlockBodyShanghai, MERGE_TIMESTAMP,
                SHANGHAI_TIMESTAMP,
            },
            header_with_proof::{
                BlockHeaderProof, HeaderWithProof, PreMergeAccumulatorProof, SszNone,
            },
        },
        jsonrpc::{params::Params, request::JsonRequest},
    },
    utils::bytes::hex_encode,
    BlockBodyKey, BlockHeaderKey, BlockReceiptsKey, Header, HistoryContentKey, HistoryContentValue,
    Receipts,
};
use trin_validation::{accumulator::PreMergeAccumulator, constants::MERGE_BLOCK_NUMBER};

/// Limit the number of requests in a single batch to avoid exceeding the
/// provider's batch size limit configuration of 100.
const BATCH_LIMIT: usize = 100;

/// Implements endpoints from the Execution API to access data from the execution layer.
/// Performs validation of the data returned from the provider.
#[derive(Clone, Debug)]
pub struct ExecutionApi {
    pub client: Client,
    pub fallback_client: Client,
    pub pre_merge_acc: PreMergeAccumulator,
}

impl ExecutionApi {
    pub async fn new(client: Client, fallback_client: Client) -> Result<Self, surf::Error> {
        // Only check that provider is connected & available if not using a test provider.
        debug!(
            "Starting ExecutionApi with primary provider: {} and fallback provider: {}",
            client
                .config()
                .base_url
                .as_ref()
                .expect("to have base url set")
                .as_str(),
            fallback_client
                .config()
                .base_url
                .as_ref()
                .expect("to have base url set")
                .as_str()
        );
        if let Err(err) = check_provider(&client).await {
            error!("Primary el provider is offline: {err:?}");
        }
        let pre_merge_acc = PreMergeAccumulator::default();
        Ok(Self {
            client,
            fallback_client,
            pre_merge_acc,
        })
    }

    /// Return a validated FullHeader & content key / value pair for the given header.
    pub async fn get_header(
        &self,
        height: u64,
        epoch_acc: Option<Arc<EpochAccumulator>>,
    ) -> anyhow::Result<(FullHeader, HistoryContentKey, HistoryContentValue)> {
        // Geth requires block numbers to be formatted using the following padding.
        let block_param = format!("0x{height:01X}");
        let params = Params::Array(vec![json!(block_param), json!(true)]);
        let request = JsonRequest::new("eth_getBlockByNumber".to_string(), params, height as u32);
        let response = self.try_request(request).await?;
        let result = response
            .get("result")
            .ok_or_else(|| anyhow!("Unable to fetch header for block: {height:?}"))?;
        let mut full_header: FullHeader = FullHeader::try_from(result.clone())?;

        // Add epoch accumulator to header if it's a pre-merge block.
        if full_header.header.number < MERGE_BLOCK_NUMBER {
            if epoch_acc.is_none() {
                bail!("Epoch accumulator is required for pre-merge blocks");
            }
            full_header.epoch_acc = epoch_acc;
        }

        // Validate header.
        if let Err(msg) = full_header.validate() {
            bail!("Header validation failed: {msg}");
        };
        // Construct content key / value pair.
        let content_key = HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey {
            block_hash: full_header.header.hash().0,
        });
        let content_value = match &full_header.epoch_acc {
            Some(epoch_acc) => {
                // Construct HeaderWithProof
                let header_with_proof =
                    construct_proof(full_header.header.clone(), epoch_acc).await?;
                // Double check that the proof is valid
                self.pre_merge_acc
                    .validate_header_with_proof(&header_with_proof)?;
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
        Ok((full_header, content_key, content_value))
    }

    /// Return a validated BlockBody content key / value for the given FullHeader.
    pub async fn get_block_body(
        &self,
        full_header: &FullHeader,
    ) -> anyhow::Result<(HistoryContentKey, HistoryContentValue)> {
        let block_body = self.get_trusted_block_body(full_header).await?;
        block_body.validate_against_header(&full_header.header)?;
        let content_key = HistoryContentKey::BlockBody(BlockBodyKey {
            block_hash: full_header.header.hash().0,
        });
        let content_value = HistoryContentValue::BlockBody(block_body);
        Ok((content_key, content_value))
    }

    /// Return an unvalidated block body for the given FullHeader.
    async fn get_trusted_block_body(&self, full_header: &FullHeader) -> anyhow::Result<BlockBody> {
        let txs = full_header.txs.clone();
        if full_header.header.timestamp > SHANGHAI_TIMESTAMP {
            if !full_header.uncles.is_empty() {
                bail!("Invalid block: Shanghai block contains uncles");
            }
            let withdrawals = match full_header.withdrawals.clone() {
                Some(val) => val,
                None => bail!("Invalid block: Shanghai block missing withdrawals"),
            };
            Ok(BlockBody::Shanghai(BlockBodyShanghai { txs, withdrawals }))
        } else if full_header.header.timestamp > MERGE_TIMESTAMP {
            if !full_header.uncles.is_empty() {
                bail!("Invalid block: Merge block contains uncles");
            }
            Ok(BlockBody::Merge(BlockBodyMerge { txs }))
        } else {
            let uncles = match full_header.uncles.len() {
                0 => vec![],
                _ => self.get_trusted_uncles(&full_header.uncles).await?,
            };
            Ok(BlockBody::Legacy(BlockBodyLegacy { txs, uncles }))
        }
    }

    /// Return unvalidated uncles for the given uncle hashes.
    async fn get_trusted_uncles(&self, hashes: &[B256]) -> anyhow::Result<Vec<Header>> {
        let batch_request = hashes
            .iter()
            .enumerate()
            .map(|(id, uncle)| {
                let uncle_hash = hex_encode(uncle);
                let params = Params::Array(vec![json!(uncle_hash), json!(false)]);
                let method = "eth_getBlockByHash".to_string();
                JsonRequest::new(method, params, id as u32)
            })
            .collect();
        let response = self.batch_requests(batch_request).await?;
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

    /// Return validated Receipts content key / value for the given FullHeader.
    pub async fn get_receipts(
        &self,
        full_header: &FullHeader,
    ) -> anyhow::Result<(HistoryContentKey, HistoryContentValue)> {
        // Build receipts
        let receipts = match full_header.txs.len() {
            0 => Receipts {
                receipt_list: vec![],
            },
            _ => {
                self.get_trusted_receipts(&full_header.tx_hashes.hashes)
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
            block_hash: full_header.header.hash().0,
        });
        let content_value = HistoryContentValue::Receipts(receipts);
        Ok((content_key, content_value))
    }

    /// Return unvalidated receipts for the given transaction hashes.
    async fn get_trusted_receipts(&self, tx_hashes: &[B256]) -> anyhow::Result<Receipts> {
        let request: Vec<JsonRequest> = tx_hashes
            .iter()
            .enumerate()
            .map(|(id, tx_hash)| {
                let tx_hash = hex_encode(tx_hash);
                let params = Params::Array(vec![json!(tx_hash)]);
                let method = "eth_getTransactionReceipt".to_string();
                JsonRequest::new(method, params, id as u32)
            })
            .collect();
        let response = self.batch_requests(request).await?;
        match serde_json::from_str(&response) {
            Ok(receipts) => Ok(receipts),
            Err(err) => {
                bail!("Unable to parse receipts from response: {response:?} error: {err:?}")
            }
        }
    }

    pub async fn get_latest_block_number(&self) -> anyhow::Result<u64> {
        let params = Params::Array(vec![json!("latest"), json!(false)]);
        let method = "eth_getBlockByNumber".to_string();
        let request = JsonRequest::new(method, params, 1);
        let response = self.try_request(request).await?;
        let result = response
            .get("result")
            .ok_or_else(|| anyhow!("Unable to fetch latest block"))?;
        let header: Header = serde_json::from_value(result.clone())?;
        Ok(header.number)
    }

    /// Used the "surf" library here instead of "ureq" since "surf" is much more capable of handling
    /// multiple async requests. Using "ureq" consistently resulted in errors as soon as the number
    /// of concurrent tasks increased significantly.
    async fn batch_requests(&self, obj: Vec<JsonRequest>) -> anyhow::Result<String> {
        let batched_request_futures = obj
            .chunks(BATCH_LIMIT)
            .map(|chunk| self.try_batch_request(chunk.to_vec()))
            .collect::<Vec<_>>();
        match join_all(batched_request_futures)
            .await
            .into_iter()
            .try_fold(Vec::new(), |mut acc, next| {
                acc.extend_from_slice(&next?);
                Ok::<Vec<Value>, Box<dyn std::error::Error>>(acc)
            }) {
            Ok(val) => Ok(serde_json::to_string(&val)?),
            Err(err) => Err(anyhow!("Unable to flatten batch request: {err:?}")),
        }
    }

    async fn try_batch_request(&self, requests: Vec<JsonRequest>) -> anyhow::Result<Vec<Value>> {
        if requests.len() > BATCH_LIMIT {
            warn!(
                "Attempting to send requests outnumbering provider request limit of {BATCH_LIMIT}."
            )
        }
        match Self::send_batch_request(&self.client, &requests).await {
            Ok(response) => Ok(response),
            Err(msg) => {
                warn!("Failed to send batch request to primary provider: {msg}");
                sleep(FALLBACK_RETRY_AFTER).await;
                match Self::send_batch_request(&self.fallback_client, &requests).await {
                    Ok(response) => Ok(response),
                    Err(msg) => {
                        bail!("Failed to send batch request to fallback provider: {msg}");
                    }
                }
            }
        }
    }

    async fn send_batch_request(
        client: &Client,
        requests: &Vec<JsonRequest>,
    ) -> anyhow::Result<Vec<Value>> {
        let result = client
            .post("")
            .body_json(&json!(requests))
            .map_err(|e| anyhow!("Unable to construct json post for batched requests: {e:?}"))?;
        let response = result
            .recv_string()
            .await
            .map_err(|err| anyhow!("Unable to request execution batch from provider: {err:?}"))?;
        serde_json::from_str::<Vec<Value>>(&response).map_err(|err| {
            anyhow!("Unable to parse execution batch from provider: {err:?} response: {response:?}")
        })
    }

    async fn try_request(&self, request: JsonRequest) -> anyhow::Result<Value> {
        match Self::send_request(&self.client, &request).await {
            Ok(response) => Ok(response),
            Err(msg) => {
                warn!("Failed to send request to primary provider, retrying with fallback provider: {msg}");
                sleep(FALLBACK_RETRY_AFTER).await;
                Self::send_request(&self.fallback_client, &request)
                    .await
                    .map_err(|err| anyhow!("Failed to send request to fallback provider: {err:?}"))
            }
        }
    }

    async fn send_request(client: &Client, request: &JsonRequest) -> anyhow::Result<Value> {
        let result = client
            .post("")
            .body_json(&request)
            .map_err(|e| anyhow!("Unable to construct json post for single request: {e:?}"))?;
        let response = result
            .recv_string()
            .await
            .map_err(|err| anyhow!("Unable to request execution payload from provider: {err:?}"))?;
        serde_json::from_str::<Value>(&response).map_err(|err| {
            anyhow!(
                "Unable to parse execution response from provider: {err:?} response: {response:?}"
            )
        })
    }
}

/// Create a proof for the given header / epoch acc
pub async fn construct_proof(
    header: Header,
    epoch_acc: &EpochAccumulator,
) -> anyhow::Result<HeaderWithProof> {
    let proof = PreMergeAccumulator::construct_proof(&header, epoch_acc)?;
    let proof = BlockHeaderProof::PreMergeAccumulatorProof(PreMergeAccumulatorProof { proof });
    Ok(HeaderWithProof { header, proof })
}

/// Check that provider is valid and accessible.
async fn check_provider(client: &Client) -> anyhow::Result<()> {
    let request = client
        .post("")
        .body_json(
            &json!({"jsonrpc": "2.0", "method": "web3_clientVersion", "params": [], "id": 1}),
        )
        .map_err(|e| anyhow!("Unable to construct json post request: {e:?}"))?;
    let response = request
        .recv_string()
        .await
        .map_err(|err| anyhow!("Unable to request execution batch from provider: {err:?}"))?;
    let response: Value = serde_json::from_str(&response).map_err(|err| anyhow!("Unable to parse json response from execution provider, it's likely unavailable/configured incorrectly: {err:?} response: {response:?}"))?;
    if response["result"].as_str().is_none() {
        bail!("Invalid response from execution provider check, it's likely unavailable/configured incorrectly");
    }
    Ok(())
}
