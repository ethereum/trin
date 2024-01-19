use anyhow::{anyhow, bail};
use ethereum_types::H256;
use futures::future::join_all;
use serde_json::{json, Value};
use surf::{
    middleware::{Middleware, Next},
    Body, Client, Config, Request, Response,
};
use tokio::time::{sleep, Duration};
use tracing::{info, warn};
use url::Url;

use crate::{
    cli::Provider,
    constants::BASE_EL_ENDPOINT,
    types::full_header::{FullHeader, FullHeaderBatch},
    PANDAOPS_CLIENT_ID, PANDAOPS_CLIENT_SECRET,
};
use ethportal_api::{
    types::{
        execution::block_body::{
            BlockBody, BlockBodyLegacy, BlockBodyMerge, BlockBodyShanghai, MERGE_TIMESTAMP,
            SHANGHAI_TIMESTAMP,
        },
        jsonrpc::{params::Params, request::JsonRequest},
    },
    utils::bytes::hex_encode,
    Header, Receipts,
};

/// Limit the number of requests in a single batch to avoid exceeding the
/// provider's batch size limit configuration of 100.
const BATCH_LIMIT: usize = 100;

/// Implements endpoints from the Execution API to access data from the execution layer.
#[derive(Clone, Debug)]
pub struct ExecutionApi {
    client: Client,
}

impl ExecutionApi {
    pub async fn new(provider: Provider) -> Result<Self, surf::Error> {
        let client = match &provider {
            Provider::PandaOps => {
                let base_el_endpoint = Url::parse(BASE_EL_ENDPOINT)
                    .expect("to be able to parse static base el endpoint url");
                Config::new()
                    .add_header("Content-Type", "application/json")?
                    .add_header("CF-Access-Client-Id", PANDAOPS_CLIENT_ID.to_string())?
                    .add_header(
                        "CF-Access-Client-Secret",
                        PANDAOPS_CLIENT_SECRET.to_string(),
                    )?
                    .set_base_url(base_el_endpoint)
                    .try_into()?
            }
            Provider::Url(url) => Config::new()
                .add_header("Content-Type", "application/json")?
                .set_base_url(url.clone())
                .try_into()?,
            Provider::Test => Config::new().try_into()?,
        };
        // Only check that provider is connected & available if not using a test provider.
        if provider != Provider::Test {
            check_provider(&client).await?;
        }
        Ok(Self { client })
    }

    /// Returns an unvalidated block body for the given FullHeader.
    pub async fn get_trusted_block_body(
        &self,
        full_header: &FullHeader,
    ) -> anyhow::Result<BlockBody> {
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

    /// Returns unvalidated receipts for the given transaction hashes.
    pub async fn get_trusted_receipts(&self, tx_hashes: &[H256]) -> anyhow::Result<Receipts> {
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
        Ok(serde_json::from_str(&response)?)
    }

    pub async fn get_latest_block_number(&self) -> anyhow::Result<u64> {
        let params = Params::Array(vec![json!("latest"), json!(false)]);
        let method = "eth_getBlockByNumber".to_string();
        let request = JsonRequest::new(method, params, 1);
        let response = self.batch_requests(vec![request]).await?;
        let response: Vec<Value> = serde_json::from_str(&response)?;
        let result = response[0]
            .get("result")
            .ok_or_else(|| anyhow!("Unable to fetch latest block"))?;
        let header: Header = serde_json::from_value(result.clone())?;
        Ok(header.number)
    }

    /// Returns unvalidated uncles for the given uncle hashes.
    async fn get_trusted_uncles(&self, hashes: &[H256]) -> anyhow::Result<Vec<Header>> {
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

    pub async fn get_header(&self, height: u64) -> anyhow::Result<FullHeader> {
        // Geth requires block numbers to be formatted using the following padding.
        let block_param = format!("0x{height:01X}");
        let params = Params::Array(vec![json!(block_param), json!(true)]);
        let batch_request = vec![JsonRequest::new(
            "eth_getBlockByNumber".to_string(),
            params,
            height as u32,
        )];
        let response = self.batch_requests(batch_request).await?;
        let batch: FullHeaderBatch = serde_json::from_str(&response)?;
        if batch.headers.len() != 1 {
            bail!("Expected 1 header, got {:#?}", batch.headers.len());
        }
        Ok(batch.headers[0].clone())
    }

    /// Used the "surf" library here instead of "ureq" since "surf" is much more capable of handling
    /// multiple async requests. Using "ureq" consistently resulted in errors as soon as the number
    /// of concurrent tasks increased significantly.
    async fn batch_requests(&self, obj: Vec<JsonRequest>) -> anyhow::Result<String> {
        let batched_request_futures = obj
            .chunks(BATCH_LIMIT)
            .map(|chunk| self.send_batch_request(chunk.to_vec()))
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

    async fn send_batch_request(&self, requests: Vec<JsonRequest>) -> anyhow::Result<Vec<Value>> {
        if requests.len() > BATCH_LIMIT {
            warn!(
                "Attempting to send requests outnumbering provider request limit of {BATCH_LIMIT}."
            )
        }
        let result = self
            .client
            .post("")
            .middleware(Retry::default())
            .body_json(&json!(requests))
            .map_err(|e| anyhow!("Unable to construct json post request: {e:?}"))?
            .recv_string()
            .await
            .map_err(|err| anyhow!("Unable to request execution batch from provider: {err:?}"));
        serde_json::from_str::<Vec<Value>>(&result?)
            .map_err(|err| anyhow!("Unable to parse execution batch from provider: {err:?}"))
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
    let response: Value = serde_json::from_str(&response).map_err(|err| anyhow!("Unable to parse json response from execution provider, it's likely unavailable/configured incorrectly: {err:?}"))?;
    if response["result"].as_str().is_none() {
        bail!("Invalid response from execution provider check, it's likely unavailable/configured incorrectly");
    }
    Ok(())
}
