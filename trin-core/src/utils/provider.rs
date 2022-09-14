use std::env;
use std::fmt;
use std::str::FromStr;

use anyhow::anyhow;
use serde_json::Value;
use ureq::Request;

use crate::cli::TrinConfig;
use crate::jsonrpc::service::dispatch_trusted_http_request;
use crate::jsonrpc::types::{JsonRequest, Params};

pub const INFURA_BASE_HTTP_URL: &str = "https://mainnet.infura.io:443/v3/";
pub const INFURA_BASE_WS_URL: &str = "wss://mainnet.infura.io:443/ws/v3/";

// Type used for parsing cli args
#[derive(Clone, Debug, PartialEq)]
pub enum TrustedProviderType {
    Infura,
    Geth,
}

impl fmt::Display for TrustedProviderType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Infura => write!(f, "infura"),
            Self::Geth => write!(f, "geth"),
        }
    }
}

type ParseError = &'static str;

impl FromStr for TrustedProviderType {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "geth" => Ok(TrustedProviderType::Geth),
            "infura" => Ok(TrustedProviderType::Infura),
            _ => panic!("Invalid trusted provider arg: {s} is not an option."),
        }
    }
}

/// Stores datatypes needed to send & receive http requests and create & maintain a websocket
/// connection. Since the websocket library's `Client` is lifetime based - we store just the url as
/// a String, which can be used to create a `Client` when necessary.
#[derive(Clone, Debug)]
pub struct TrustedProvider {
    pub http: Request,
    pub ws: Option<String>,
}

impl TrustedProvider {
    pub fn from_trin_config(trin_config: &TrinConfig) -> Self {
        let trusted_http_client = match trin_config.trusted_provider {
            TrustedProviderType::Infura => build_infura_http_client_from_env(),
            TrustedProviderType::Geth => match trin_config.geth_url.clone() {
                Some(val) => build_geth_http_client_from_env(val),
                None => {
                    panic!("Must supply --geth-url cli flag to use Geth as a trusted provider.")
                }
            },
        };
        let trusted_ws_url = match trin_config.trusted_provider {
            TrustedProviderType::Infura => Some(build_infura_ws_url_from_env()),
            TrustedProviderType::Geth => {
                panic!("Geth connection is not currently supported over websockets.")
            }
        };
        Self {
            http: trusted_http_client,
            ws: trusted_ws_url,
        }
    }

    pub fn dispatch_http_request(&self, method: String, params: Params) -> anyhow::Result<Value> {
        let request = JsonRequest {
            jsonrpc: "2.0".to_string(),
            params,
            method,
            id: 1,
        };
        match dispatch_trusted_http_request(request, self.http.clone()) {
            Ok(val) => Ok(serde_json::from_str(&val)?),
            Err(msg) => {
                return Err(anyhow!(
                    "Unable to request validation data from trusted provider: {:?}",
                    msg
                ))
            }
        }
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

fn build_infura_http_client_from_env() -> ureq::Request {
    let infura_project_id = get_infura_project_id_from_env();
    let infura_url = format!("{INFURA_BASE_HTTP_URL}{infura_project_id}");
    ureq::post(&infura_url)
}

fn build_infura_ws_url_from_env() -> String {
    let infura_project_id = get_infura_project_id_from_env();
    format!("{INFURA_BASE_WS_URL}{infura_project_id}")
}

fn get_geth_client_id_from_env() -> String {
    match env::var("GETH_CLIENT_ID") {
        Ok(val) => val,
        Err(_) => panic!(
            "Must supply Geth client id as environment variable, like:\n\
            GETH_CLIENT_ID=\"your-key-here\" trin"
        ),
    }
}

fn get_geth_client_secret_from_env() -> String {
    match env::var("GETH_CLIENT_SECRET") {
        Ok(val) => val,
        Err(_) => panic!(
            "Must supply Geth client secret as environment variable, like:\n\
            GETH_CLIENT_SECRET=\"your-key-here\" trin"
        ),
    }
}

fn build_geth_http_client_from_env(geth_url: String) -> ureq::Request {
    let client_id = get_geth_client_id_from_env();
    let client_secret = get_geth_client_secret_from_env();
    ureq::post(&geth_url)
        .set("Content-Type", "application/json")
        .set("CF-Access-Client-Id", client_id.as_str())
        .set("CF-Access-Client-Secret", client_secret.as_str())
}
