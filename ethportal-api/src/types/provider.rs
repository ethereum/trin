use std::env;
use std::fmt;
use std::str::FromStr;

use anyhow::anyhow;
use serde_json::Value;
use url::Url;

use crate::types::jsonrpc::request::JsonRequest;
use serde_json::json;

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
    pub http: surf::Request,
}

impl TrustedProvider {
    pub fn from_trin_config(trin_config: &TrinConfig) -> Self {
        let trusted_http_client = match trin_config.trusted_provider {
            TrustedProviderType::Infura => build_infura_http_client_from_env(),
            TrustedProviderType::Pandaops => match &trin_config.trusted_provider_url {
                Some(val) => build_pandaops_http_client_from_env(val.to_string()),
                None => {
                    panic!("Must supply --trusted-provider-url cli flag to use pandaops as a trusted provider.")
                }
            },
            TrustedProviderType::Custom => match trin_config.trusted_provider_url.clone() {
                Some(val) => build_custom_provider_http_client(val),
                None => build_custom_provider_http_client(
                    Url::parse(DEFAULT_LOCAL_PROVIDER)
                        .expect("Could not parse default local provider."),
                ),
            },
        };
        Self {
            http: trusted_http_client,
        }
    }

    pub async fn dispatch_http_request(
        &self,
        method: String,
        params: Params,
    ) -> anyhow::Result<Value> {
        let request = json_request(method, params, 1);

        let client = surf::Client::new();
        let mut result: surf::Request = self.http.clone();
        result
            .body_json(&json!(request))
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
        let mut request: surf::Request = self.http.clone();
        request
            .body_json(&json!(obj))
            .map_err(|e| anyhow!("Unable to construct json post request: {e:?}"))?;
        let result = client.recv_string(request).await;
        result.map_err(|_| anyhow!("Unable to request batch from geth"))
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

pub fn build_infura_http_client_from_env() -> surf::Request {
    let infura_project_id = get_infura_project_id_from_env();
    let infura_url = format!("{INFURA_BASE_HTTP_URL}{infura_project_id}");
    surf::Request::from(surf::post(infura_url))
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

pub fn build_pandaops_http_client_from_env(pandaops_url: String) -> surf::Request {
    let client_id = get_pandaops_client_id_from_env();
    let client_secret = get_pandaops_client_secret_from_env();
    surf::Request::from(
        surf::post(pandaops_url)
            .header("Content-Type", "application/json")
            .header("CF-Access-Client-Id", client_id.as_str())
            .header("CF-Access-Client-Secret", client_secret.as_str()),
    )
}

pub fn build_custom_provider_http_client(node_url: Url) -> surf::Request {
    surf::Request::from(surf::post(node_url.as_str()).header("Content-Type", "application/json"))
}

pub fn json_request(method: String, params: Params, id: u32) -> JsonRequest {
    JsonRequest {
        jsonrpc: "2.0".to_string(),
        params,
        method,
        id,
    }
}
