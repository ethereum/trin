use std::io::prelude::*;
use std::os::unix::net::UnixStream;

use hyper::{self, Body, Client, Method, Request};
use log::info;
use serde_json::{self, Value};
use thiserror::Error;

use trin_core::jsonrpc::types::Params;
use trin_core::portalnet::U256;

#[derive(Clone)]
pub struct JsonRpcEndpoint {
    pub method: &'static str,
    pub id: &'static u8,
    pub params: Params,
}

fn validate_endpoint_response(id: &u8, result: &Value) {
    match id {
        0 => {
            assert_eq!(result.as_str().unwrap(), "trin v0.1.0");
        }
        1 => {
            let enr = result.get("enr").unwrap();
            assert!(enr.is_string());
            assert!(enr.as_str().unwrap().contains("enr:"));
            assert!(result.get("nodeId").unwrap().is_string());
        }
        2 => {
            let local_key = result.get("localKey").unwrap();
            assert!(local_key.is_string());
            assert!(local_key.as_str().unwrap().contains("0x"));
            assert!(result.get("buckets").unwrap().is_array());
        }
        3 => {
            assert!(result.is_string());
            assert!(result.as_str().unwrap().contains("0x"));
        }
        4 => {
            assert_eq!(result.as_str().unwrap(), U256::from(u64::MAX).to_string());
        }
        5 => {
            assert_eq!(result.as_str().unwrap(), U256::from(u64::MAX).to_string());
        }
        _ => panic!("Unsupported endpoint"),
    };
    info!("RPC endpoint: id #{:?} returned a valid response.", id);
}

impl JsonRpcEndpoint {
    pub fn all_endpoints() -> Vec<JsonRpcEndpoint> {
        vec![
            JsonRpcEndpoint {
                method: "web3_clientVersion",
                id: &0,
                params: Params::None,
            },
            JsonRpcEndpoint {
                method: "discv5_nodeInfo",
                id: &1,
                params: Params::None,
            },
            JsonRpcEndpoint {
                method: "discv5_routingTableInfo",
                id: &2,
                params: Params::None,
            },
            JsonRpcEndpoint {
                method: "eth_blockNumber",
                id: &3,
                params: Params::None,
            },
            JsonRpcEndpoint {
                method: "overlay_dataRadius",
                id: &4,
                params: Params::Array(vec![Value::String("history".to_string())]),
            },
            JsonRpcEndpoint {
                method: "overlay_dataRadius",
                id: &5,
                params: Params::Array(vec![Value::String("state".to_string())]),
            },
        ]
    }

    pub fn to_jsonrpc(&self) -> String {
        match self.params {
            Params::None => format!(
                r#"
                    {{
                        "jsonrpc":"2.0",
                        "id": {},
                        "method": "{}"
                    }}"#,
                self.id, self.method
            ),
            _ => format!(
                r#"
                    {{
                        "jsonrpc":"2.0",
                        "id": {},
                        "method": "{}",
                        "params": {}
                    }}"#,
                self.id,
                self.method,
                serde_json::to_string(&self.params).unwrap()
            ),
        }
    }
}

#[allow(clippy::never_loop)]
pub async fn test_jsonrpc_endpoints_over_ipc(target_ipc_path: String) {
    for endpoint in JsonRpcEndpoint::all_endpoints() {
        info!("Testing over IPC: {:?}", endpoint.method);
        let mut stream = UnixStream::connect(&target_ipc_path).unwrap();
        let v: Value = serde_json::from_str(&endpoint.to_jsonrpc()).unwrap();
        let data = serde_json::to_vec(&v).unwrap();
        stream.write_all(&data).unwrap();
        stream.flush().unwrap();
        let deser = serde_json::Deserializer::from_reader(stream);
        for obj in deser.into_iter::<Value>() {
            let response_obj = obj.unwrap();
            match get_response_result(response_obj) {
                Ok(result) => validate_endpoint_response(endpoint.id, &result),
                Err(msg) => panic!(
                    "Jsonrpc error for endpoint id #{:?}: {:?}",
                    endpoint.id, msg
                ),
            }
            // break out of loop here since EOF is not sent, and loop will hang
            break;
        }
    }
}

#[derive(Error, Debug)]
pub enum JsonRpcResponseError {
    #[error("JsonRpc response contains an error: {0}")]
    Error(String),

    #[error("Invalid JsonRpc response")]
    Invalid(),
}

fn get_response_result(response: Value) -> Result<Value, JsonRpcResponseError> {
    match response.get("result") {
        Some(result) => Ok(result.clone()),
        None => match response.get("error") {
            Some(error) => Err(JsonRpcResponseError::Error(error.to_string())),
            None => Err(JsonRpcResponseError::Invalid()),
        },
    }
}

pub async fn test_jsonrpc_endpoints_over_http(target_http_address: String) {
    let client = Client::new();
    for endpoint in JsonRpcEndpoint::all_endpoints() {
        info!("Testing over HTTP: {:?}", endpoint.method);
        let json_string = endpoint.to_jsonrpc();
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("http://{}", target_http_address))
            .header("content-type", "application/json")
            .body(Body::from(json_string))
            .unwrap();
        let resp = client.request(req).await.unwrap();
        let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let response_obj: Value = serde_json::from_slice(&body).unwrap();
        match get_response_result(response_obj) {
            Ok(result) => validate_endpoint_response(endpoint.id, &result),
            Err(msg) => panic!(
                "Jsonrpc error for endpoint id #{:?}: {:?}",
                endpoint.id, msg
            ),
        }
    }
}
