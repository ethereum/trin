use std::io::prelude::*;
use std::os::unix::net::UnixStream;
use std::time::Duration;
use std::{fs, panic, process};

use hyper::{self, Body, Client, Method, Request};
use log::{debug, info};
use serde_json::{self, Value};
use thiserror::Error;

use crate::cli::PeertestConfig;
use trin_core::jsonrpc::types::Params;
use trin_core::portalnet::U256;

#[derive(Clone)]
pub struct JsonRpcEndpoint {
    pub method: String,
    pub id: u8,
    pub params: Params,
}

fn validate_endpoint_response(method: &str, result: &Value) {
    match method {
        "web3_clientVersion" => {
            assert_eq!(result.as_str().unwrap(), "trin v0.1.0");
        }
        "discv5_nodeInfo" => {
            let enr = result.get("enr").unwrap();
            assert!(enr.is_string());
            assert!(enr.as_str().unwrap().contains("enr:"));
            assert!(result.get("nodeId").unwrap().is_string());
        }
        "discv5_routingTableInfo" => {
            let local_key = result.get("localKey").unwrap();
            assert!(local_key.is_string());
            assert!(local_key.as_str().unwrap().contains("0x"));
            assert!(result.get("buckets").unwrap().is_array());
        }
        "portal_historyRadius" => {
            assert_eq!(result.as_str().unwrap(), U256::from(u64::MAX).to_string());
        }
        "portal_stateRadius" => {
            assert_eq!(result.as_str().unwrap(), U256::from(u64::MAX).to_string());
        }
        "portal_historyPing" => {
            assert!(result.is_string());
            assert!(result.as_str().unwrap().contains("data_radius"));
            assert!(result.as_str().unwrap().contains("payload"));
        }
        "portal_statePing" => {
            assert!(result.is_string());
            assert!(result.as_str().unwrap().contains("data_radius"));
            assert!(result.as_str().unwrap().contains("payload"));
        }
        _ => panic!("Unsupported endpoint"),
    };
    info!("{:?} returned a valid response.", method);
}

impl JsonRpcEndpoint {
    pub fn all_endpoints(_target_node: String) -> Vec<JsonRpcEndpoint> {
        vec![
            JsonRpcEndpoint {
                method: "web3_clientVersion".to_string(),
                id: 0,
                params: Params::None,
            },
            JsonRpcEndpoint {
                method: "discv5_nodeInfo".to_string(),
                id: 1,
                params: Params::None,
            },
            JsonRpcEndpoint {
                method: "discv5_routingTableInfo".to_string(),
                id: 2,
                params: Params::None,
            },
            JsonRpcEndpoint {
                method: "portal_historyRadius".to_string(),
                id: 4,
                params: Params::None,
            },
            JsonRpcEndpoint {
                method: "portal_stateRadius".to_string(),
                id: 5,
                params: Params::None,
            },
            /*
            JsonRpcEndpoint {
                method: "portal_statePing".to_string(),
                id: 6,
                params: Params::Array(vec![Value::String(target_node.clone())]),
            },
            JsonRpcEndpoint {
                method: "portal_historyPing".to_string(),
                id: 7,
                params: Params::Array(vec![Value::String(target_node)]),
            },
            */
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
                    "params":{}
                }}"#,
                self.id,
                self.method,
                serde_json::to_string(&self.params).unwrap()
            ),
        }
    }
}

#[allow(clippy::never_loop)]
pub async fn test_jsonrpc_endpoints_over_ipc(peertest_config: PeertestConfig) {
    // setup cleanup handler if tests panic
    let original_panic = panic::take_hook();
    let ipc_path = peertest_config.web3_ipc_path.clone();
    panic::set_hook(Box::new(move |panic_info| {
        if let Err(err) = fs::remove_file(&ipc_path) {
            debug!(
                "Peertest panic hook: Skipped removing {} because: {}",
                ipc_path, err
            );
        };
        original_panic(panic_info);
        process::exit(1);
    }));

    info!("Testing IPC path: {}", peertest_config.web3_ipc_path);
    for endpoint in JsonRpcEndpoint::all_endpoints(peertest_config.target_node) {
        info!("Testing IPC method: {:?}", endpoint.method);
        let mut stream = UnixStream::connect(&peertest_config.web3_ipc_path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("Couldn't set read timeout");
        let v: Value = serde_json::from_str(&endpoint.to_jsonrpc()).unwrap();
        let data = serde_json::to_vec(&v).unwrap();
        stream.write_all(&data).unwrap();
        stream.flush().unwrap();
        let deser = serde_json::Deserializer::from_reader(stream);
        for obj in deser.into_iter::<Value>() {
            let response_obj = match obj {
                Ok(val) => val,
                Err(err) => panic!(
                    "json deserialization error. (Timeouts typically give an 'os error 11'): {}",
                    err
                ),
            };
            match get_response_result(response_obj) {
                Ok(result) => validate_endpoint_response(&endpoint.method, &result),
                Err(msg) => panic!(
                    "Jsonrpc error for {:?} endpoint: {:?}",
                    endpoint.method, msg
                ),
            }
            // break out of loop here since EOF is not sent, and loop will hang
            break;
        }
    }
    fs::remove_file(&peertest_config.web3_ipc_path).unwrap();
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

pub async fn test_jsonrpc_endpoints_over_http(peertest_config: PeertestConfig) {
    let client = Client::new();
    for endpoint in JsonRpcEndpoint::all_endpoints(peertest_config.target_node) {
        info!("Testing over HTTP: {:?}", endpoint.method);
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("http://{}", peertest_config.target_http_address))
            .header("content-type", "application/json")
            .body(Body::from(endpoint.to_jsonrpc()))
            .unwrap();
        let resp = client.request(req).await.unwrap();
        let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let response_obj: Value = serde_json::from_slice(&body).unwrap();
        match get_response_result(response_obj) {
            Ok(result) => validate_endpoint_response(&endpoint.method, &result),
            Err(msg) => panic!(
                "Jsonrpc error for {:?} endpoint: {:?}",
                endpoint.method, msg
            ),
        }
    }
}
