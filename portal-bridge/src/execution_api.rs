use anyhow::{anyhow, bail};
use ethereum_types::H256;
use ethportal_api::types::jsonrpc::params::Params;
use ethportal_api::types::jsonrpc::request::JsonRequest;
use ethportal_api::utils::bytes::hex_encode;
use ethportal_api::{Header, Receipts};
use serde_json::{json, Value};

use crate::full_header::{FullHeader, FullHeaderBatch};
use crate::pandaops::PandaOpsMiddleware;

/// Implements endpoints from the Execution API to access data from the execution layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionApi {
    middleware: PandaOpsMiddleware,
}

impl ExecutionApi {
    pub fn new(middleware: PandaOpsMiddleware) -> Self {
        Self { middleware }
    }

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
        let response = self.middleware.batch_requests(request).await?;
        Ok(serde_json::from_str(&response)?)
    }

    pub async fn get_latest_block_number(&self) -> anyhow::Result<u64> {
        let params = Params::Array(vec![json!("latest"), json!(false)]);
        let method = "eth_getBlockByNumber".to_string();
        let request = JsonRequest::new(method, params, 1);
        let response = self.middleware.batch_requests(vec![request]).await?;
        let response: Vec<Value> = serde_json::from_str(&response)?;
        let result = response[0]
            .get("result")
            .ok_or_else(|| anyhow!("Unable to fetch latest block"))?;
        let header: Header = serde_json::from_value(result.clone())?;
        Ok(header.number)
    }

    pub async fn get_trusted_uncles(&self, hashes: &[H256]) -> anyhow::Result<Vec<Header>> {
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
        let response = self.middleware.batch_requests(batch_request).await?;
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
        let response = self.middleware.batch_requests(batch_request).await?;
        let batch: FullHeaderBatch = serde_json::from_str(&response)?;
        if batch.headers.len() != 1 {
            bail!("Expected 1 header, got {:#?}", batch.headers.len());
        }
        Ok(batch.headers[0].clone())
    }
}
