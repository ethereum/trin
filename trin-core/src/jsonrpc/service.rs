use std::{
    io::{self},
    sync::{Arc, RwLock},
};

use serde_json::json;
use thiserror::Error;
use ureq::{self, Request};

use crate::jsonrpc::types::JsonRequest;

pub struct JsonRpcExiter {
    should_exit: Arc<RwLock<bool>>,
}

impl JsonRpcExiter {
    pub fn new() -> Self {
        JsonRpcExiter {
            should_exit: Arc::new(RwLock::new(false)),
        }
    }

    pub fn exit(&self) {
        let mut flag = self.should_exit.write().unwrap();
        *flag = true;
    }

    pub fn is_exiting(&self) -> bool {
        let flag = self.should_exit.read().unwrap();
        *flag
    }
}

impl Default for JsonRpcExiter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Error, Debug)]
pub enum HttpParseError {
    #[error("Unable to parse http request: {0}")]
    InvalidRequest(String),
}

// Handle all http requests served by the trusted provider
pub fn dispatch_trusted_http_request(
    obj: JsonRequest,
    trusted_http_client: Request,
) -> Result<String, String> {
    match proxy_to_url(&obj, trusted_http_client) {
        Ok(result_body) => Ok(std::str::from_utf8(&result_body).unwrap().to_owned()),
        Err(err) => Err(json!({
            "jsonrpc": "2.0",
            "id": obj.id,
            "error": format!("Infura failure: {}", err),
        })
        .to_string()),
    }
}

fn proxy_to_url(request: &JsonRequest, trusted_http_client: Request) -> io::Result<Vec<u8>> {
    match trusted_http_client.send_json(ureq::json!(request)) {
        Ok(response) => match response.into_string() {
            Ok(val) => Ok(val.as_bytes().to_vec()),
            Err(msg) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Error decoding response: {:?}", msg),
            )),
        },
        Err(ureq::Error::Status(code, _response)) => Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Responded with status code: {:?}", code),
        )),
        Err(err) => Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Request failure: {:?}", err),
        )),
    }
}
