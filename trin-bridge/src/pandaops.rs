use crate::bridge::Retry;
use crate::constants::{BASE_CL_ENDPOINT, BASE_EL_ENDPOINT};
use crate::full_header::{FullHeader, FullHeaderBatch};
use crate::{PANDAOPS_CLIENT_ID, PANDAOPS_CLIENT_SECRET};
use anyhow::{anyhow, bail};
use ethereum_types::H256;
use ethportal_api::types::jsonrpc::params::Params;
use ethportal_api::types::jsonrpc::request::JsonRequest;
use ethportal_api::utils::bytes::hex_encode;
use ethportal_api::{Header, Receipts};
use serde_json::{json, Value};

pub struct PandaOpsMiddleware {
    pub base_el_endpoint: String,
    pub base_cl_endpoint: String,
    pub client_id: String,
    pub client_secret: String,
}

impl PandaOpsMiddleware {
    pub fn new(
        base_el_endpoint: String,
        base_cl_endpoint: String,
        client_id: String,
        client_secret: String,
    ) -> Self {
        Self {
            base_el_endpoint,
            base_cl_endpoint,
            client_id,
            client_secret,
        }
    }
}

impl Default for PandaOpsMiddleware {
    fn default() -> Self {
        Self {
            base_el_endpoint: BASE_EL_ENDPOINT.to_string(),
            base_cl_endpoint: BASE_CL_ENDPOINT.to_string(),
            client_id: PANDAOPS_CLIENT_ID.clone(),
            client_secret: PANDAOPS_CLIENT_SECRET.clone(),
        }
    }
}

impl PandaOpsMiddleware {
    /// Used the "surf" library here instead of "ureq" since "surf" is much more capable of handling
    /// multiple async requests. Using "ureq" consistently resulted in errors as soon as the number of
    /// concurrent tasks increased significantly.
    async fn batch_request(&self, obj: Vec<JsonRequest>) -> anyhow::Result<String> {
        let result = surf::post(self.base_el_endpoint.clone())
            .middleware(Retry::default())
            .body_json(&json!(obj))
            .map_err(|e| anyhow!("Unable to construct json post request: {e:?}"))?
            .header("Content-Type", "application/json".to_string())
            .header("CF-Access-Client-Id", self.client_id.clone())
            .header("CF-Access-Client-Secret", self.client_secret.clone())
            .recv_string()
            .await;

        result.map_err(|err| anyhow!("Unable to request execution batch from pandaops: {err:?}"))
    }

    #[allow(dead_code)] // FIXME: Remove this once we have a use case for this function (e.g. requesting consensus data)
    pub(crate) async fn request(&self, endpoint: String) -> anyhow::Result<String> {
        let result = surf::get(endpoint)
            .header("Content-Type", "application/json".to_string())
            .header("CF-Access-Client-Id", self.client_id.clone())
            .header("CF-Access-Client-Secret", self.client_secret.clone())
            .recv_string()
            .await;
        result.map_err(|err| anyhow!("Unable to request consensus block from pandaops: {err:?}"))
    }

    pub(crate) async fn get_trusted_receipts(
        &self,
        tx_hashes: &[H256],
    ) -> anyhow::Result<Receipts> {
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
        let response = self.batch_request(request).await?;
        Ok(serde_json::from_str(&response)?)
    }

    pub(crate) async fn get_latest_block_number(&self) -> anyhow::Result<u64> {
        let params = Params::Array(vec![json!("latest"), json!(false)]);
        let method = "eth_getBlockByNumber".to_string();
        let request = JsonRequest::new(method, params, 1);
        let response = self.batch_request(vec![request]).await?;
        let response: Vec<Value> = serde_json::from_str(&response)?;
        let result = response[0]
            .get("result")
            .ok_or_else(|| anyhow!("Unable to fetch latest block"))?;
        let header: Header = serde_json::from_value(result.clone())?;
        Ok(header.number)
    }

    pub(crate) async fn get_trusted_uncles(&self, hashes: &[H256]) -> anyhow::Result<Vec<Header>> {
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
        let response = self.batch_request(batch_request).await?;
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

    pub(crate) async fn get_header(&self, height: u64) -> anyhow::Result<FullHeader> {
        // Geth requires block numbers to be formatted using the following padding.
        let block_param = format!("0x{height:01X}");
        let params = Params::Array(vec![json!(block_param), json!(true)]);
        let batch_request = vec![JsonRequest::new(
            "eth_getBlockByNumber".to_string(),
            params,
            height as u32,
        )];
        let response = self.batch_request(batch_request).await?;
        let batch: FullHeaderBatch = serde_json::from_str(&response)?;
        if batch.headers.len() != 1 {
            bail!("Expected 1 header, got {:#?}", batch.headers.len());
        }
        Ok(batch.headers[0].clone())
    }
}
