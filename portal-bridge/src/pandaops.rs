use crate::bridge::Retry;
use crate::constants::{BASE_CL_ENDPOINT, BASE_EL_ENDPOINT};
use crate::{PANDAOPS_CLIENT_ID, PANDAOPS_CLIENT_SECRET};
use anyhow::anyhow;
use ethportal_api::types::jsonrpc::request::JsonRequest;
use serde_json::json;

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
    /// multiple async requests. Using "ureq" consistently resulted in errors as soon as the number of
    /// concurrent tasks increased significantly.
    pub async fn batch_request(&self, obj: Vec<JsonRequest>) -> anyhow::Result<String> {
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
