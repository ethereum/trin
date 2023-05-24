use std::env;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use anyhow::anyhow;
use serde_json::Value;
use url::Url;

use crate::types::jsonrpc::request::JsonRequest;
use serde_json::json;
use surf::middleware::{Middleware, Next};
use surf::{Body, Client, Request, Response};
use tokio::time::sleep;
use tracing::info;

use super::cli::TrinConfig;
use super::jsonrpc::params::Params;

pub const INFURA_BASE_HTTP_URL: &str = "https://mainnet.infura.io:443/v3/";
pub const DEFAULT_LOCAL_PROVIDER: &str = "http://127.0.0.1:8545";

// Type used for parsing cli args
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustedProviderType {
    Infura,
    Pandaops,
    Custom,
}

impl fmt::Display for TrustedProviderType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Infura => write!(f, "infura"),
            Self::Pandaops => write!(f, "pandaops"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

type ParseError = &'static str;

impl FromStr for TrustedProviderType {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pandaops" => Ok(TrustedProviderType::Pandaops),
            "infura" => Ok(TrustedProviderType::Infura),
            "custom" => Ok(TrustedProviderType::Custom),
            _ => panic!("Invalid trusted provider arg: {s} is not an option."),
        }
    }
}

/// Stores datatypes needed to send & receive http requests and create & maintain a websocket
/// connection. Since the websocket library's `Client` is lifetime based - we store just the url as
/// a String, which can be used to create a `Client` when necessary.
#[derive(Clone, Debug)]
pub struct TrustedProvider {
    pub execution_url: Url,
    pub beacon_base_url: Option<Url>,
    pub trusted_provider_type: TrustedProviderType,
}

impl TrustedProvider {
    pub fn from_trin_config(trin_config: &TrinConfig) -> Self {
        let trusted_execution_url = match trin_config.trusted_provider {
            TrustedProviderType::Infura => build_infura_execution_url_from_env(),
            TrustedProviderType::Pandaops => match trin_config.trusted_provider_url.clone() {
                Some(val) => val,
                None => {
                    panic!("Must supply --trusted-provider-url cli flag to use pandaops as a trusted provider.")
                }
            },
            TrustedProviderType::Custom => match trin_config.trusted_provider_url.clone() {
                Some(val) => val,
                None => Url::parse(DEFAULT_LOCAL_PROVIDER)
                    .expect("Could not parse default local provider."),
            },
        };
        Self {
            execution_url: trusted_execution_url,
            beacon_base_url: None,
            trusted_provider_type: TrustedProviderType::Infura,
        }
    }

    pub async fn dispatch_http_request(
        &self,
        method: String,
        params: Params,
    ) -> anyhow::Result<Value> {
        let json_request = json_request(method, params, 1);

        let client = surf::Client::new();

        let url: Url = self.execution_url.clone();
        let mut result = self.add_headers(surf::Request::from(surf::post(url)));
        result
            .body_json(&json!(json_request))
            .map_err(|e| anyhow!("Unable to construct json post request: {e:?}"))?;
        let response = client.recv_string(result).await;

        match response {
            Ok(val) => Ok(serde_json::from_str(&val)?),
            Err(err) => Err(anyhow!("Unable to request: {err:?}",)),
        }
    }

    /// Used the "surf" library here instead of "ureq" since "surf" is much more capable of handling
    /// multiple async requests. Using "ureq" consistently resulted in errors as soon as the number of
    /// concurrent tasks increased significantly.
    pub async fn batch_request(&self, obj: Vec<JsonRequest>) -> anyhow::Result<String> {
        let client = surf::Client::new();
        let url: Url = self.execution_url.clone();
        let mut request = self.add_headers(surf::Request::from(
            surf::post(url).middleware(Retry::default()),
        ));
        request
            .body_json(&json!(obj))
            .map_err(|e| anyhow!("Unable to construct json post request: {e:?}"))?;
        let result = client.recv_string(request).await;
        result.map_err(|_| anyhow!("Unable to request batch from geth"))
    }

    pub async fn beacon_request(&self, endpoint: String) -> anyhow::Result<String> {
        if let Some(beacon_base_url) = self.beacon_base_url.clone() {
            let client = surf::Client::new();
            let request = self.add_headers(surf::Request::from(surf::get(
                beacon_base_url.join(&endpoint)?,
            )));
            let result = client.recv_string(request).await;
            result.map_err(|_| anyhow!("Unable to request consensus block from beacon URL"))
        } else {
            Err(anyhow!("Beacon base URL wasn't provided"))
        }
    }

    fn add_headers(&self, mut request: Request) -> surf::Request {
        match self.trusted_provider_type {
            TrustedProviderType::Infura => {}
            TrustedProviderType::Pandaops => {
                let client_id = get_pandaops_client_id_from_env();
                let client_secret = get_pandaops_client_secret_from_env();
                request.append_header("Content-Type", "application/json");
                request.append_header("CF-Access-Client-Id", client_id.as_str());
                request.append_header("CF-Access-Client-Secret", client_secret.as_str());
            }
            TrustedProviderType::Custom => {
                request.append_header("Content-Type", "application/json");
            }
        }
        request
    }
}

fn get_infura_project_id_from_env() -> String {
    match env::var("TRIN_INFURA_PROJECT_ID") {
        Ok(val) => val,
        Err(_) => panic!(
            "Must supply Infura key as environment variable, like:\n\
            TRIN_INFURA_PROJECT_ID=\"your-key-here\" trin"
        ),
    }
}

pub fn build_infura_execution_url_from_env() -> Url {
    let infura_project_id = get_infura_project_id_from_env();
    Url::parse(&format!("{INFURA_BASE_HTTP_URL}{infura_project_id}"))
        .expect("Couldn't parse infura url")
}

fn get_pandaops_client_id_from_env() -> String {
    match env::var("PANDAOPS_CLIENT_ID") {
        Ok(val) => val,
        Err(_) => panic!(
            "Must supply pandaops client id as environment variable, like:\n\
            PANDAOPS_CLIENT_ID=\"your-key-here\" trin"
        ),
    }
}

fn get_pandaops_client_secret_from_env() -> String {
    match env::var("PANDAOPS_CLIENT_SECRET") {
        Ok(val) => val,
        Err(_) => panic!(
            "Must supply pandaops client secret as environment variable, like:\n\
            PANDAOPS_CLIENT_SECRET=\"your-key-here\" trin"
        ),
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

pub fn json_request(method: String, params: Params, id: u32) -> JsonRequest {
    JsonRequest {
        jsonrpc: "2.0".to_string(),
        params,
        method,
        id,
    }
}
