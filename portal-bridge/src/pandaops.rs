use anyhow::anyhow;
use futures::future::join_all;
use serde_json::{json, Value};
use surf::{
    middleware::{Middleware, Next},
    Body, Client, Request, Response,
};
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

use crate::{
    constants::{BASE_CL_ENDPOINT, BASE_EL_ENDPOINT},
    PANDAOPS_CLIENT_ID, PANDAOPS_CLIENT_SECRET,
};
use ethportal_api::types::jsonrpc::request::JsonRequest;

/// Limit the number of requests in a single batch to avoid exceeding the
/// provider's batch size limit configuration of 100.
const BATCH_LIMIT: usize = 100;

#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// multiple async requests. Using "ureq" consistently resulted in errors as soon as the number
    /// of concurrent tasks increased significantly.
    pub async fn batch_requests(&self, obj: Vec<JsonRequest>) -> anyhow::Result<String> {
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
            warn!("Attempting to send requests outnumbering pandaops limit")
        }
        let result = surf::post(self.base_el_endpoint.clone())
            .middleware(Retry::default())
            .body_json(&json!(requests))
            .map_err(|e| anyhow!("Unable to construct json post request: {e:?}"))?
            .header("Content-Type", "application/json".to_string())
            .header("CF-Access-Client-Id", self.client_id.clone())
            .header("CF-Access-Client-Secret", self.client_secret.clone())
            .recv_string()
            .await
            .map_err(|err| anyhow!("Unable to request execution batch from pandaops: {err:?}"));
        serde_json::from_str::<Vec<Value>>(&result?)
            .map_err(|err| anyhow!("Unable to parse execution batch from pandaops: {err:?}"))
    }

    pub async fn request(&self, endpoint: String) -> anyhow::Result<String> {
        let result = surf::get(endpoint)
            .header("Content-Type", "application/json".to_string())
            .header("CF-Access-Client-Id", self.client_id.clone())
            .header("CF-Access-Client-Secret", self.client_secret.clone())
            .recv_string()
            .await;
        result.map_err(|err| anyhow!("Unable to request consensus block from pandaops: {err:?}"))
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
