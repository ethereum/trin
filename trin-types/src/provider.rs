use std::env;
use std::fmt;
use std::str::FromStr;

use anyhow::anyhow;
use serde_json::Value;
use url::Url;

use std::io;

use serde_json::json;
use ureq::{self, Request};

use crate::cli::TrinConfig;
use crate::jsonrpc::params::Params;

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
    pub http: Request,
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

    pub fn dispatch_http_request(&self, method: String, params: Params) -> anyhow::Result<Value> {
        let request = ureq::json!({
            "jsonrpc": "2.0".to_string(),
            "params": params,
            "method": method,
            "id": 1,
        });

        match dispatch_trusted_http_request(request, self.http.clone()) {
            Ok(val) => Ok(serde_json::from_str(&val)?),
            Err(err) => Err(anyhow!(
                "Unable to request validation data from trusted provider: {err:?}",
            )),
        }
    }
}

// Handle all http requests served by the trusted provider
fn dispatch_trusted_http_request(
    obj: Value,
    trusted_http_client: Request,
) -> Result<String, String> {
    match proxy_to_url(&obj, trusted_http_client) {
        Ok(result_body) => Ok(std::str::from_utf8(&result_body)
            .map_err(|e| format!("When decoding utf8 from proxied provider: {e:?}"))?
            .to_owned()),
        Err(err) => Err(json!({
            "jsonrpc": "2.0",
            "id": obj.get("id"),
            "error": format!("Infura failure: {err}"),
        })
        .to_string()),
    }
}

fn proxy_to_url(request: &Value, trusted_http_client: Request) -> io::Result<Vec<u8>> {
    match trusted_http_client.send_json(ureq::json!(request)) {
        Ok(response) => match response.into_string() {
            Ok(val) => Ok(val.as_bytes().to_vec()),
            Err(msg) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Error decoding response: {msg:?}"),
            )),
        },
        Err(ureq::Error::Status(code, _response)) => Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Responded with status code: {code:?}"),
        )),
        Err(err) => Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Request failure: {err:?}"),
        )),
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

pub fn build_pandaops_http_client_from_env(pandaops_url: String) -> ureq::Request {
    let client_id = get_pandaops_client_id_from_env();
    let client_secret = get_pandaops_client_secret_from_env();
    ureq::post(&pandaops_url)
        .set("Content-Type", "application/json")
        .set("CF-Access-Client-Id", client_id.as_str())
        .set("CF-Access-Client-Secret", client_secret.as_str())
}

fn build_custom_provider_http_client(node_url: Url) -> ureq::Request {
    ureq::post(node_url.as_str()).set("Content-Type", "application/json")
}
