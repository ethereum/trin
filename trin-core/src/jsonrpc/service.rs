use std::io::{self};

use serde_json::json;
use thiserror::Error;
use ureq::{self, Request};

use crate::jsonrpc::types::JsonRequest;

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
        Ok(result_body) => Ok(std::str::from_utf8(&result_body)
            .map_err(|e| format!("When decoding utf8 from proxied provider: {e:?}"))?
            .to_owned()),
        Err(err) => Err(json!({
            "jsonrpc": "2.0",
            "id": obj.id,
            "error": format!("Infura failure: {err}"),
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
