use std::io::prelude::*;
use std::os::unix::net::UnixStream;
use std::slice::Iter;

use hyper::{self, Body, Client, Method, Request};
use log::info;
use serde_json::{self, Value};

use trin_core::portalnet::U256;

#[derive(Copy, Clone)]
pub struct JsonRpcEndpoint {
    pub method: &'static str,
    pub id: &'static u8,
}

const ALL_ENDPOINTS: [JsonRpcEndpoint; 6] = [
    JsonRpcEndpoint {
        method: "web3_clientVersion",
        id: &0,
    },
    JsonRpcEndpoint {
        method: "discv5_nodeInfo",
        id: &1,
    },
    JsonRpcEndpoint {
        method: "discv5_routingTableInfo",
        id: &2,
    },
    JsonRpcEndpoint {
        method: "eth_blockNumber",
        id: &3,
    },
    JsonRpcEndpoint {
        method: "portalHistory_dataRadius",
        id: &4,
    },
    JsonRpcEndpoint {
        method: "portalState_dataRadius",
        id: &5,
    },
];

fn validate_endpoint_response(method: &str, result: &Value) {
    match method {
        "web3_clientVersion" => {
            assert_eq!(result.as_str().unwrap(), "trin 0.0.1-alpha");
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
        "eth_blockNumber" => {
            assert!(result.is_string());
            assert!(result.as_str().unwrap().contains("0x"));
        }
        "portalHistory_dataRadius" => {
            assert_eq!(result.as_str().unwrap(), U256::from(u64::MAX).to_string());
        }
        "portalState_dataRadius" => {
            assert_eq!(result.as_str().unwrap(), U256::from(u64::MAX).to_string());
        }
        _ => panic!("Unsupported endpoint"),
    };
    info!("{:?} returned a valid response.", method);
}

impl JsonRpcEndpoint {
    pub fn all_endpoints() -> Iter<'static, Self> {
        ALL_ENDPOINTS.iter()
    }

    pub fn to_jsonrpc(self) -> Vec<u8> {
        let data = format!(
            r#"
            {{
                "jsonrpc":"2.0",
                "id": {},
                "method": "{}"
            }}"#,
            self.id, self.method
        );
        let v: Value = serde_json::from_str(&data).unwrap();
        serde_json::to_vec(&v).unwrap()
    }
}

pub async fn test_jsonrpc_endpoints_over_ipc() {
    for endpoint in JsonRpcEndpoint::all_endpoints() {
        info!("Testing over IPC: {:?}", endpoint.method);
        let mut stream = UnixStream::connect("/tmp/trin-jsonrpc.ipc").unwrap();
        stream.write_all(&endpoint.to_jsonrpc()).unwrap();
        stream.flush().unwrap();
        let deser = serde_json::Deserializer::from_reader(stream);
        for obj in deser.into_iter::<Value>() {
            let response_obj = obj.unwrap();
            let result = response_obj.get("result").unwrap();
            validate_endpoint_response(endpoint.method, result);
        }
    }
}

pub async fn test_jsonrpc_endpoints_over_http() {
    let client = Client::new();
    for endpoint in JsonRpcEndpoint::all_endpoints() {
        info!("Testing over HTTP: {:?}", endpoint.method);
        let json_string = format!(
            r#"{{"jsonrpc":"2.0","id":0,"method":"{}","params":[]}}"#,
            endpoint.method
        );
        let req = Request::builder()
            .method(Method::POST)
            .uri("http://127.0.0.1:8545")
            .header("content-type", "application/json")
            .body(Body::from(json_string))
            .unwrap();
        let resp = client.request(req).await.unwrap();
        let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let body_json: Value = serde_json::from_slice(&body).unwrap();
        let result = body_json.get("result").unwrap();
        validate_endpoint_response(endpoint.method, result);
    }
}
