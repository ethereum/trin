use std::io::prelude::*;
#[cfg(unix)]
use std::os::unix;
use std::panic;
use std::time::Duration;

use anyhow::anyhow;
use hyper::{self, Body, Client, Method, Request};
use log::info;
use serde_json::{self, json, Value};

use crate::cli::PeertestConfig;
use crate::AllPeertestNodes;
use trin_core::jsonrpc::types::{NodesParams, Params};

#[derive(Clone)]
pub struct JsonRpcEndpoint {
    pub method: String,
    pub id: u8,
    pub params: Params,
}

/// Default data radius value: U256::from(u64::MAX)
const DATA_RADIUS: &str = "18446744073709551615";
/// Default enr seq value
const ENR_SEQ: &str = "1";

fn validate_endpoint_response(method: &str, result: &Value, _peertest_nodes: &AllPeertestNodes) {
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
            assert_eq!(result.as_str().unwrap(), DATA_RADIUS);
        }
        "portal_stateRadius" => {
            assert_eq!(result.as_str().unwrap(), DATA_RADIUS);
        }
        "portal_historyPing" => {
            assert_eq!(
                result.get("dataRadius").unwrap().as_str().unwrap(),
                DATA_RADIUS
            );
            assert_eq!(
                result.get("enrSeq").unwrap().as_str().unwrap(),
                ENR_SEQ.to_string()
            );
        }
        "portal_historyFindNodes" => {
            let nodes = NodesParams::try_from(result).unwrap();
            assert_eq!(nodes.total, 1u8);
            assert!(
                // Exact enrs count is somewhat flaky, usually b/w 3-5
                !nodes.enrs.is_empty()
            );
        }
        "portal_statePing" => {
            assert_eq!(
                result.get("dataRadius").unwrap().as_str().unwrap(),
                DATA_RADIUS
            );
            assert_eq!(
                result.get("enrSeq").unwrap().as_str().unwrap(),
                ENR_SEQ.to_string()
            );
        }
        "portal_stateFindNodes" => {
            let nodes = NodesParams::try_from(result).unwrap();
            assert_eq!(nodes.total, 1u8);
            assert!(
                // Exact enrs count is somewhat flaky, usually b/w 3-5
                !nodes.enrs.is_empty()
            );
        }
        _ => panic!("Unsupported endpoint"),
    };
    info!("{:?} returned a valid response.", method);
}

impl JsonRpcEndpoint {
    pub fn all_endpoints(all_peertest_nodes: &AllPeertestNodes) -> Vec<JsonRpcEndpoint> {
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
            JsonRpcEndpoint {
                method: "portal_statePing".to_string(),
                id: 6,
                params: Params::Array(vec![
                    Value::String(all_peertest_nodes.bootnode.enr.clone()),
                    Value::String(DATA_RADIUS.to_owned()),
                ]),
            },
            JsonRpcEndpoint {
                method: "portal_historyPing".to_string(),
                id: 7,
                params: Params::Array(vec![
                    Value::String(all_peertest_nodes.bootnode.enr.clone()),
                    Value::String(DATA_RADIUS.to_owned()),
                ]),
            },
            JsonRpcEndpoint {
                method: "portal_historyFindNodes".to_string(),
                id: 8,
                params: Params::Array(vec![
                    Value::String(all_peertest_nodes.bootnode.enr.clone()),
                    Value::Array(vec![json!(256)]),
                ]),
            },
            JsonRpcEndpoint {
                method: "portal_stateFindNodes".to_string(),
                id: 9,
                params: Params::Array(vec![
                    Value::String(all_peertest_nodes.bootnode.enr.clone()),
                    Value::Array(vec![json!(256)]),
                ]),
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
                    "params":{}
                }}"#,
                self.id,
                self.method,
                serde_json::to_string(&self.params).unwrap()
            ),
        }
    }
}

#[cfg(unix)]
fn get_ipc_stream(ipc_path: &str) -> unix::net::UnixStream {
    unix::net::UnixStream::connect(ipc_path).unwrap()
}

#[cfg(windows)]
fn get_ipc_stream(ipc_path: &str) -> uds_windows::UnixStream {
    uds_windows::UnixStream::connect(ipc_path).unwrap()
}

pub fn make_ipc_request(
    ipc_path: &str,
    endpoint: JsonRpcEndpoint,
) -> anyhow::Result<serde_json::Value> {
    let mut stream = get_ipc_stream(ipc_path);
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("Couldn't set read timeout");

    let v: Value = serde_json::from_str(&endpoint.to_jsonrpc()).unwrap();
    let data = serde_json::to_vec(&v).unwrap();
    stream.write_all(&data).unwrap();
    stream.flush().unwrap();
    let deser = serde_json::Deserializer::from_reader(stream);
    let next_obj = deser.into_iter::<Value>().next();
    let response_obj = next_obj.ok_or(anyhow!("Empty JsonRpc response"))?;
    get_response_result(response_obj)
}

pub fn get_enode(ipc_path: &str) -> anyhow::Result<String> {
    let info_endpoint = JsonRpcEndpoint {
        method: "discv5_nodeInfo".to_string(),
        id: 1,
        params: Params::None,
    };
    let result = make_ipc_request(ipc_path, info_endpoint).map_err(|jsonerr| {
        anyhow!(
            "Error while trying to get enode for client at ipc_path {ipc_path:?} endpoint: {jsonerr:?}"
        )
    })?;
    match result.get("enr") {
        Some(val) => match val.as_str() {
            Some(enr) => Ok(enr.to_owned()),
            None => Err(anyhow!("Reported ENR value was not a string")),
        },
        None => Err(anyhow!("'enr' field not found in nodeInfo response")),
    }
}

#[allow(clippy::never_loop)]
pub async fn test_jsonrpc_endpoints_over_ipc(
    peertest_config: PeertestConfig,
    all_peertest_nodes: &AllPeertestNodes,
) {
    info!("Testing IPC path: {}", peertest_config.target_ipc_path);
    for endpoint in JsonRpcEndpoint::all_endpoints(all_peertest_nodes) {
        info!("Testing IPC method: {:?}", endpoint.method);
        let mut stream = get_ipc_stream(&peertest_config.target_ipc_path);
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("Couldn't set read timeout");
        let v: Value = serde_json::from_str(&endpoint.to_jsonrpc()).unwrap();
        let data = serde_json::to_vec(&v).unwrap();
        stream.write_all(&data).unwrap();
        stream.flush().unwrap();
        let deser = serde_json::Deserializer::from_reader(stream);
        for obj in deser.into_iter::<Value>() {
            match get_response_result(obj) {
                Ok(result) => {
                    validate_endpoint_response(&endpoint.method, &result, all_peertest_nodes)
                }
                Err(msg) => panic!(
                    "Jsonrpc error for {:?} endpoint ('os error 11' means timeout): {:?}",
                    endpoint.method, msg
                ),
            }
            // break out of loop here since EOF is not sent, and loop will hang
            break;
        }
    }
}

fn get_response_result(response: Result<Value, serde_json::Error>) -> anyhow::Result<Value> {
    let response =
        response.map_err(|err| anyhow!("Deserialize failed on JsonRpc response: {err:?}"))?;
    match response.get("result") {
        Some(result) => Ok(result.clone()),
        None => match response.get("error") {
            Some(error) => Err(anyhow!("JsonRpc response contains an error: {error:?}")),
            None => Err(anyhow!("Invalid object in JsonRpc response")),
        },
    }
}

pub async fn test_jsonrpc_endpoints_over_http(
    peertest_config: PeertestConfig,
    all_peertest_nodes: &AllPeertestNodes,
) {
    let client = Client::new();
    for endpoint in JsonRpcEndpoint::all_endpoints(all_peertest_nodes) {
        info!("Testing over HTTP: {:?}", endpoint.method);
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("http://{}", peertest_config.target_http_address))
            .header("content-type", "application/json")
            .body(Body::from(endpoint.to_jsonrpc()))
            .unwrap();
        let resp = client.request(req).await.unwrap();
        let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let response_obj = serde_json::from_slice(&body);
        match get_response_result(response_obj) {
            Ok(result) => validate_endpoint_response(&endpoint.method, &result, all_peertest_nodes),
            Err(msg) => panic!(
                "Jsonrpc error for {:?} endpoint: {:?}",
                endpoint.method, msg
            ),
        }
    }
}
