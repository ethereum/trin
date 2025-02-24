use std::sync::Arc;

use alloy::primitives::B256;
use anyhow::{anyhow, bail};
use ethportal_api::{
    types::{
        execution::{
            accumulator::EpochAccumulator,
            block_body::{
                BlockBody, BlockBodyLegacy, BlockBodyMerge, BlockBodyShanghai, MERGE_TIMESTAMP,
                SHANGHAI_TIMESTAMP,
            },
            header_with_proof_new::{BlockHeaderProof, HeaderWithProof},
        },
        jsonrpc::{params::Params, request::JsonRequest},
    },
    utils::bytes::{hex_decode, hex_encode},
    Header, HistoryContentKey, HistoryContentValue, Receipts,
};
use futures::future::join_all;
use serde_json::{json, Value};
use tokio::time::sleep;
use tracing::{debug, error, warn};
use trin_validation::{
    accumulator::PreMergeAccumulator, constants::MERGE_BLOCK_NUMBER,
    header_validator::HeaderValidator,
};
use url::Url;

use crate::{
    cli::{url_to_client, ClientWithBaseUrl},
    constants::{FALLBACK_RETRY_AFTER, GET_RECEIPTS_RETRY_AFTER},
    types::full_header::FullHeader,
};

/// Limit the number of requests in a single batch to avoid exceeding the
/// provider's batch size limit configuration of 100.
const BATCH_LIMIT: usize = 100;

/// Implements endpoints from the Execution API to access data from the execution layer.
/// Performs validation of the data returned from the provider.
#[derive(Clone, Debug)]
pub struct ExecutionApi {
    pub primary: Url,
    pub fallback: Url,
    pub header_validator: HeaderValidator,
    pub request_timeout: u64,
}

impl ExecutionApi {
    pub async fn new(
        primary: Url,
        fallback: Url,
        request_timeout: u64,
    ) -> Result<Self, reqwest_middleware::Error> {
        // Only check that provider is connected & available if not using a test provider.
        debug!(
            "Starting ExecutionApi with primary provider: {primary} and fallback provider: {fallback}",
        );
        let client = url_to_client(primary.clone(), request_timeout).map_err(|err| {
            anyhow!("Unable to create primary client for execution data provider: {err:?}")
        })?;
        if let Err(err) = check_provider(&client).await {
            error!("Primary el provider is offline: {err:?}");
        }
        let header_validator = HeaderValidator::default();
        Ok(Self {
            primary,
            fallback,
            header_validator,
            request_timeout,
        })
    }

    /// Return a validated FullHeader & content by hash and number key / value pair for the given
    /// header.
    pub async fn get_header(
        &self,
        height: u64,
        epoch_acc: Option<Arc<EpochAccumulator>>,
    ) -> anyhow::Result<(
        FullHeader,
        HistoryContentKey, // BlockHeaderByHash
        HistoryContentKey, // BlockHeaderByNumber
        HistoryContentValue,
    )> {
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
        // Construct header by hash content key / value pair.
        let header_by_hash_content_key =
            HistoryContentKey::new_block_header_by_hash(full_header.header.hash());
        // Construct header by number content key / value pair.
        let header_by_number_content_key =
            HistoryContentKey::new_block_header_by_number(full_header.header.number);
        let content_value = match &full_header.epoch_acc {
            Some(epoch_acc) => {
                // Construct HeaderWithProof
                let header_with_proof =
                    construct_proof(full_header.header.clone(), epoch_acc).await?;
                // Double check that the proof is valid
                self.header_validator
                    .validate_header_with_proof(&header_with_proof)?;
                HistoryContentValue::BlockHeaderWithProof(header_with_proof)
            }
            None => {
                bail!("Generate header with historical_roots or historical_summaries proof");
            }
        };
        Ok((
            full_header,
            header_by_hash_content_key,
            header_by_number_content_key,
            content_value,
        ))
    }

    /// Return a validated BlockBody content key / value for the given FullHeader.
    pub async fn get_block_body(
        &self,
        full_header: &FullHeader,
    ) -> anyhow::Result<(HistoryContentKey, HistoryContentValue)> {
        let block_body = self.get_trusted_block_body(full_header).await?;
        block_body.validate_against_header(&full_header.header)?;
        let content_key = HistoryContentKey::new_block_body(full_header.header.hash());
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
            _ => self.get_trusted_receipts(full_header.header.number).await?,
        };

        // Validate Receipts
        let receipts_root = receipts.root()?;
        if receipts_root != full_header.header.receipts_root {
            bail!(
                "Receipts root doesn't match header receipts root: {receipts_root:?} - {:?}",
                full_header.header.receipts_root
            );
        }
        let content_key = HistoryContentKey::new_block_receipts(full_header.header.hash());
        let content_value = HistoryContentValue::Receipts(receipts);
        Ok((content_key, content_value))
    }

    /// Return unvalidated receipts for the given transaction hashes.
    async fn get_trusted_receipts(&self, height: u64) -> anyhow::Result<Receipts> {
        let block_param = format!("0x{height:01X}");
        // At this custom retry mechanism, the json-rpc is unreliable, we only call this function if
        // we know the receipts should exist, but they might not be ready yet for any reason and the
        // full-node will retry null, so we will just retry 3 times as we know they have it.
        for _ in 0..3 {
            let params = Params::Array(vec![json!(block_param)]);
            let request = JsonRequest::new("eth_getBlockReceipts".to_string(), params, 1);
            let response = self.try_request(request).await?;
            let result = response.get("result").ok_or_else(|| {
                anyhow!("Unable to fetch block receipts result for height: {height:?} {response:?}")
            })?;

            // Check if the result is null, if so, sleep and retry.
            if result.is_null() {
                sleep(GET_RECEIPTS_RETRY_AFTER).await;
                continue;
            }
            return serde_json::from_value(response).map_err(|err| {
                anyhow!("Unable to parse receipts from provider response: {err:?}")
            });
        }
        bail!("Unable to fetch receipts for block: {height:?}");
    }

    pub async fn get_block_hash(&self, height: u64) -> anyhow::Result<B256> {
        let block_param = format!("0x{height:01X}");
        let params = Params::Array(vec![json!(block_param), json!(false)]);
        let request = JsonRequest::new("eth_getBlockByNumber".to_string(), params, 1);
        let response = self.try_request(request).await?;
        let result = response
            .get("result")
            .ok_or_else(|| anyhow!("Unable to fetch block hash result for block: {height:?}"))?;
        let hash = result
            .get("hash")
            .ok_or_else(|| anyhow!("Unable to fetch block hash for block: {height:?}"))?;
        let hash = hex_decode(
            hash.as_str()
                .ok_or_else(|| anyhow!("Unable to decode block hash"))?,
        )?;
        Ok(B256::from_slice(&hash))
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
        let client = url_to_client(self.primary.clone(), self.request_timeout).map_err(|err| {
            anyhow!("Unable to create primary client for execution data provider: {err:?}")
        })?;
        match Self::send_batch_request(&client, &requests).await {
            Ok(response) => Ok(response),
            Err(msg) => {
                warn!("Failed to send batch request to primary provider: {msg}");
                sleep(FALLBACK_RETRY_AFTER).await;
                let client =
                    url_to_client(self.fallback.clone(), self.request_timeout).map_err(|err| {
                        anyhow!(
                            "Unable to create fallback client for execution data provider: {err:?}"
                        )
                    })?;
                Self::send_batch_request(&client, &requests)
                    .await
                    .map_err(|err| {
                        anyhow!("Failed to send batch request to fallback provider: {err}")
                    })
            }
        }
    }

    async fn send_batch_request(
        client: &ClientWithBaseUrl,
        requests: &Vec<JsonRequest>,
    ) -> anyhow::Result<Vec<Value>> {
        let response = client
            .post("")?
            .json(&requests)
            .send()
            .await
            .map_err(|err| anyhow!("Unable to request execution batch from provider: {err:?}"))?;
        response
            .json::<Vec<Value>>()
            .await
            .map_err(|err| anyhow!("Unable to parse execution batch from provider: {err:?}"))
    }

    async fn try_request(&self, request: JsonRequest) -> anyhow::Result<Value> {
        let client = url_to_client(self.primary.clone(), self.request_timeout).map_err(|err| {
            anyhow!("Unable to create primary client for execution data provider: {err:?}")
        })?;
        match Self::send_request(&client, &request).await {
            Ok(response) => Ok(response),
            Err(msg) => {
                warn!("Failed to send request to primary provider, retrying with fallback provider: {msg}");
                sleep(FALLBACK_RETRY_AFTER).await;
                let client =
                    url_to_client(self.fallback.clone(), self.request_timeout).map_err(|err| {
                        anyhow!(
                            "Unable to create fallback client for execution data provider: {err:?}"
                        )
                    })?;
                Self::send_request(&client, &request)
                    .await
                    .map_err(|err| anyhow!("Failed to send request to fallback provider: {err:?}"))
            }
        }
    }

    async fn send_request(
        client: &ClientWithBaseUrl,
        request: &JsonRequest,
    ) -> anyhow::Result<Value> {
        let request = client
            .post("")?
            .json(&request)
            .build()
            .map_err(|e| anyhow!("Unable to construct JSON POST for single request: {e:?}"))?;
        let response = client
            .execute(request)
            .await
            .map_err(|err| anyhow!("Unable to request execution payload from provider: {err:?}"))?;
        let response_text = response
            .text()
            .await
            .map_err(|e| anyhow!("Unable to read response body: {e:?}"))?;
        serde_json::from_str::<Value>(&response_text).map_err(|err| {
            anyhow!(
            "Unable to parse execution response from provider: {err:?} response: {response_text:?}",
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
    let proof = BlockHeaderProof::HistoricalHashes(proof);
    Ok(HeaderWithProof { header, proof })
}

/// Check that provider is valid and accessible.
async fn check_provider(client: &ClientWithBaseUrl) -> anyhow::Result<()> {
    let request = client
        .post("")?
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "web3_clientVersion",
            "params": [],
            "id": 1,
        }))
        .build()
        .map_err(|e| anyhow!("Unable to construct json post request: {e:?}"))?;
    let response = client
        .execute(request)
        .await
        .map_err(|err| anyhow!("Unable to request execution batch from provider: {err:?}"))?;
    let response_text = response
        .text()
        .await
        .map_err(|e| anyhow!("Unable to read response body: {e:?}"))?;
    let response_json: Value = serde_json::from_str(&response_text).map_err(|err| {
    anyhow!(
        "Unable to parse json response from execution provider, it's likely unavailable/configured incorrectly: {err:?} response: {response_text:?}",
    )
})?;
    if response_json["result"].as_str().is_none() {
        bail!("Invalid response from execution provider check, it's likely unavailable/configured incorrectly");
    }
    Ok(())
}
