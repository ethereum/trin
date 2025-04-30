use std::collections::HashMap;

use alloy::{
    consensus::{Block, BlockBody as AlloyBlockBody, Header, TxEnvelope},
    rpc::types::Block as RpcBlock,
};
use alloy_hardforks::EthereumHardforks;
use anyhow::{anyhow, bail, ensure};
use ethportal_api::{
    types::{
        execution::{
            accumulator::EpochAccumulator,
            block_body::BlockBody,
            header_with_proof::{BlockHeaderProof, HeaderWithProof},
        },
        jsonrpc::{params::Params, request::JsonRequest},
        network_spec::network_spec,
    },
    HistoryContentKey, HistoryContentValue, Receipts,
};
use serde_json::{json, Value};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use trin_validation::accumulator::PreMergeAccumulator;
use url::Url;

use super::http_client::{ClientWithBaseUrl, ContentType};
use crate::constants::FALLBACK_RETRY_AFTER;

/// Limit the number of requests in a single batch to avoid exceeding the
/// provider's batch size limit configuration of 10.
const BATCH_LIMIT: usize = 10;

/// Implements endpoints from the Execution API to access data from the execution layer.
/// Performs validation of the data returned from the provider.
#[derive(Clone, Debug)]
pub struct ExecutionApi {
    pub primary: Url,
    pub fallback: Url,
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
        let client = ClientWithBaseUrl::new(primary.clone(), request_timeout, ContentType::Json)
            .map_err(|err| {
                anyhow!("Unable to create primary client for execution data provider: {err:?}")
            })?;
        if let Err(err) = check_provider(&client).await {
            error!("Primary el provider is offline: {err:?}");
        }
        Ok(Self {
            primary,
            fallback,
            request_timeout,
        })
    }

    /// Return a full block
    pub async fn get_block(&self, height: u64) -> anyhow::Result<Block<TxEnvelope>> {
        // Geth requires block numbers to be formatted using the following padding.
        let block_param = format!("0x{height:01X}");
        let params = Params::Array(vec![json!(block_param), json!(true)]);
        let request = JsonRequest::new("eth_getBlockByNumber".to_string(), params, height as u32);
        let response = self.try_request(request).await?;
        let result = response
            .get("result")
            .ok_or_else(|| anyhow!("Unable to fetch block: {height:?}"))?;
        let block = serde_json::from_str::<RpcBlock>(&result.to_string())?;
        ensure!(
            network_spec().is_paris_active_at_block(block.header.number),
            "We only support post-merge blocks"
        );
        Ok(AlloyBlockBody {
            transactions: block
                .transactions
                .into_transactions()
                .map(|transaction| transaction.into_inner())
                .collect(),
            ommers: vec![],
            withdrawals: block.withdrawals,
        }
        .into_block(block.header.into_consensus()))
    }

    /// Return a validated BlockBody content key / value for the given Block.
    pub async fn get_block_body(
        &self,
        block: &Block<TxEnvelope>,
    ) -> anyhow::Result<(HistoryContentKey, HistoryContentValue)> {
        let block_body = BlockBody(block.body.clone());
        block_body.validate_against_header(&block.header)?;
        let content_key = HistoryContentKey::new_block_body(block.header.hash_slow());
        let content_value = HistoryContentValue::BlockBody(block_body);
        Ok((content_key, content_value))
    }

    pub async fn get_receipts<I>(&self, block_range: I) -> anyhow::Result<HashMap<u64, Receipts>>
    where
        I: IntoIterator<Item = u64>,
    {
        let mut batch_request = vec![];
        let mut block_numbers = vec![];

        for (id, block_number) in block_range.into_iter().enumerate() {
            let block_param = format!("0x{block_number:01X}");
            let params = Params::Array(vec![json!(block_param)]);
            let request = JsonRequest::new("eth_getBlockReceipts".to_string(), params, id as u32);
            batch_request.push(request);
            block_numbers.push(block_number);
        }

        let batch_request_len = batch_request.len();
        let mut batch_requests_sent = 0;
        let mut receipts = HashMap::new();
        for (chunk, block_numbers) in batch_request
            .chunks(BATCH_LIMIT)
            .zip(block_numbers.chunks(BATCH_LIMIT))
        {
            info!(
                "Sending batch requests {}/{} ({:.2}%)",
                batch_requests_sent,
                batch_request_len,
                (batch_requests_sent as f64 / batch_request_len as f64) * 100.0
            );
            let responses = self
                .try_batch_request(chunk.to_vec())
                .await
                .map_err(|err| anyhow!("Batch request failed: {err:?}"))?;
            for (res, block_number) in responses.into_iter().zip(block_numbers.iter()) {
                let receipt: Receipts = serde_json::from_value(res).map_err(|err| {
                    anyhow!("Unable to parse receipts for block {block_number} from provider response: {err:?}")
                })?;
                receipts.insert(*block_number, receipt);
            }
            batch_requests_sent += chunk.len();
        }

        Ok(receipts)
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

    async fn try_batch_request(&self, requests: Vec<JsonRequest>) -> anyhow::Result<Vec<Value>> {
        if requests.len() > BATCH_LIMIT {
            warn!(
                "Attempting to send requests outnumbering provider request limit of {BATCH_LIMIT}."
            )
        }
        let client = ClientWithBaseUrl::new(
            self.primary.clone(),
            self.request_timeout,
            ContentType::Json,
        )
        .map_err(|err| {
            anyhow!("Unable to create primary client for execution data provider: {err:?}")
        })?;
        match Self::send_batch_request(&client, &requests).await {
            Ok(response) => Ok(response),
            Err(msg) => {
                warn!("Failed to send batch request to primary provider: {msg}");
                sleep(FALLBACK_RETRY_AFTER).await;
                let client = ClientWithBaseUrl::new(
                    self.fallback.clone(),
                    self.request_timeout,
                    ContentType::Json,
                )
                .map_err(|err| {
                    anyhow!("Unable to create fallback client for execution data provider: {err:?}")
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
        let client = ClientWithBaseUrl::new(
            self.primary.clone(),
            self.request_timeout,
            ContentType::Json,
        )
        .map_err(|err| {
            anyhow!("Unable to create primary client for execution data provider: {err:?}")
        })?;
        match Self::send_request(&client, &request).await {
            Ok(response) => Ok(response),
            Err(msg) => {
                warn!("Failed to send request to primary provider, retrying with fallback provider: {msg}");
                sleep(FALLBACK_RETRY_AFTER).await;
                let client = ClientWithBaseUrl::new(
                    self.fallback.clone(),
                    self.request_timeout,
                    ContentType::Json,
                )
                .map_err(|err| {
                    anyhow!("Unable to create fallback client for execution data provider: {err:?}")
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
