#[cfg(unix)]
use std::os::unix;
use std::{io::prelude::*, panic, time::Duration};

use anyhow::anyhow;
use hyper::{self, Body, Client, Method, Request};
use log::info;
use serde_json::{self, json, Value};

use crate::{cli::PeertestConfig, Peertest};
use trin_core::{
    jsonrpc::types::{NodesParams, Params},
    portalnet::types::{
        content_key::{AccountTrieNode, BlockHeader, HistoryContentKey, StateContentKey},
        messages::SszEnr,
    },
    utils::bytes::hex_encode,
};

/// Default data radius value: U256::from(u64::MAX)
const DATA_RADIUS: &str = "18446744073709551615";
/// Default enr seq value
const ENR_SEQ: &str = "1";
/// Default block hash for generating History content key
const BLOCK_HASH: [u8; 32] = [
    0xd1, 0xc3, 0x90, 0x62, 0x4d, 0x3b, 0xd4, 0xe4, 0x09, 0xa6, 0x1a, 0x85, 0x8e, 0x5d, 0xcc, 0x55,
    0x17, 0x72, 0x9a, 0x91, 0x70, 0xd0, 0x14, 0xa6, 0xc9, 0x65, 0x30, 0xd6, 0x4d, 0xd8, 0x62, 0x1d,
];
/// Default node hash for generating State content key
const NODE_HASH: [u8; 32] = [
    0xb8, 0xbe, 0x79, 0x03, 0xae, 0xe7, 0x3b, 0x8f, 0x6a, 0x59, 0xcd, 0x44, 0xa1, 0xf5, 0x2c, 0x62,
    0x14, 0x8e, 0x1f, 0x37, 0x6c, 0x0d, 0xfa, 0x1f, 0x5f, 0x77, 0x3a, 0x98, 0x66, 0x6e, 0xfc, 0x2b,
];
/// Default state root for generating State content key
const STATE_ROOT: [u8; 32] = [
    0xd1, 0xc3, 0x90, 0x62, 0x4d, 0x3b, 0xd4, 0xe4, 0x09, 0xa6, 0x1a, 0x85, 0x8e, 0x5d, 0xcc, 0x55,
    0x17, 0x72, 0x9a, 0x91, 0x70, 0xd0, 0x14, 0xa6, 0xc9, 0x65, 0x30, 0xd6, 0x4d, 0xd8, 0x62, 0x1d,
];

#[derive(Clone)]
pub struct JsonRpcRequest {
    pub method: String,
    pub id: u8,
    pub params: Params,
}

impl JsonRpcRequest {
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

struct Test<VF>
where
    VF: Fn(&Value, &Peertest),
{
    request: JsonRpcRequest,
    validation_function: VF,
}

impl<VF> Test<VF>
where
    VF: Fn(&Value, &Peertest),
{
    fn new(request: JsonRpcRequest, validation_function: VF) -> Test<impl Fn(&Value, &Peertest)> {
        Self {
            request,
            validation_function,
        }
    }

    fn validate(&self, result: &Value, peertest: &Peertest) {
        (self.validation_function)(result, peertest)
    }
}

fn all_tests(peertest: &Peertest) -> Vec<Test<impl Fn(&Value, &Peertest)>> {
    vec![
        Test::new(
            JsonRpcRequest {
                method: "web3_clientVersion".to_string(),
                id: 0,
                params: Params::None,
            },
            validate_web3_client_version as fn(&Value, &Peertest),
        ),
        Test::new(
            JsonRpcRequest {
                method: "discv5_nodeInfo".to_string(),
                id: 1,
                params: Params::None,
            },
            validate_discv5_node_info,
        ),
        Test::new(
            JsonRpcRequest {
                method: "discv5_routingTableInfo".to_string(),
                id: 2,
                params: Params::None,
            },
            validate_discv5_routing_table_info,
        ),
        Test::new(
            JsonRpcRequest {
                method: "portal_historyRadius".to_string(),
                id: 3,
                params: Params::None,
            },
            validate_portal_history_radius,
        ),
        Test::new(
            JsonRpcRequest {
                method: "portal_stateRadius".to_string(),
                id: 4,
                params: Params::None,
            },
            validate_portal_state_radius,
        ),
        Test::new(
            JsonRpcRequest {
                method: "portal_statePing".to_string(),
                id: 5,
                params: Params::Array(vec![
                    Value::String(peertest.bootnode.enr.to_base64()),
                    Value::String(DATA_RADIUS.to_owned()),
                ]),
            },
            validate_portal_state_ping,
        ),
        Test::new(
            JsonRpcRequest {
                method: "portal_historyPing".to_string(),
                id: 6,
                params: Params::Array(vec![
                    Value::String(peertest.bootnode.enr.to_base64()),
                    Value::String(DATA_RADIUS.to_owned()),
                ]),
            },
            validate_portal_history_ping,
        ),
        // Test FindNodes with 256 distance -> Routing Table enrs
        Test::new(
            JsonRpcRequest {
                method: "portal_historyFindNodes".to_string(),
                id: 7,
                params: Params::Array(vec![
                    Value::String(peertest.bootnode.enr.to_base64()),
                    Value::Array(vec![json!(256u16)]),
                ]),
            },
            validate_portal_find_nodes,
        ),
        // Test FindNodes with 0 distance -> Peer enr
        Test::new(
            JsonRpcRequest {
                method: "portal_historyFindNodes".to_string(),
                id: 8,
                params: Params::Array(vec![
                    Value::String(peertest.bootnode.enr.to_base64()),
                    Value::Array(vec![json!(0u16)]),
                ]),
            },
            validate_portal_find_nodes_zero_distance,
        ),
        // Test FindNodes with 256 distance -> Routing Table enrs
        Test::new(
            JsonRpcRequest {
                method: "portal_stateFindNodes".to_string(),
                id: 9,
                params: Params::Array(vec![
                    Value::String(peertest.bootnode.enr.to_base64()),
                    Value::Array(vec![json!(256u16)]),
                ]),
            },
            validate_portal_find_nodes,
        ),
        // Test FindNodes with 0 distance -> Peer enr
        Test::new(
            JsonRpcRequest {
                method: "portal_stateFindNodes".to_string(),
                id: 10,
                params: Params::Array(vec![
                    Value::String(peertest.bootnode.enr.to_base64()),
                    Value::Array(vec![json!(0u16)]),
                ]),
            },
            validate_portal_find_nodes_zero_distance,
        ),
        Test::new(
            JsonRpcRequest {
                method: "portal_historyStore".to_string(),
                id: 11,
                params: Params::Array(vec![
                    Value::String(hex_encode(Into::<Vec<u8>>::into(
                        HistoryContentKey::BlockHeader(BlockHeader {
                            chain_id: 1,
                            block_hash: BLOCK_HASH,
                        }),
                    ))),
                    // todo: replace with valid content
                    Value::String("0x01".to_string()),
                ]),
            },
            validate_portal_store,
        ),
        Test::new(
            JsonRpcRequest {
                method: "portal_stateStore".to_string(),
                id: 12,
                params: Params::Array(vec![
                    Value::String(hex_encode(Into::<Vec<u8>>::into(
                        StateContentKey::AccountTrieNode(AccountTrieNode {
                            node_hash: NODE_HASH,
                            state_root: STATE_ROOT,
                            path: vec![1, 2, 0, 1].into(),
                        }),
                    ))),
                    // todo: replace with valid content
                    Value::String("0x02".to_string()),
                ]),
            },
            validate_portal_store,
        ),
        // Test store endpoint with invalid content key
        Test::new(
            JsonRpcRequest {
                method: "portal_historyStore".to_string(),
                id: 11,
                params: Params::Array(vec![
                    Value::String("0x1234".to_string()),
                    Value::String("0x01".to_string()),
                ]),
            },
            validate_portal_store_with_invalid_content_key,
        ),
        // Test store endpoint with invalid content key
        Test::new(
            JsonRpcRequest {
                method: "portal_stateStore".to_string(),
                id: 12,
                params: Params::Array(vec![
                    Value::String("0x1234".to_string()),
                    Value::String("0x02".to_string()),
                ]),
            },
            validate_portal_store_with_invalid_content_key,
        ),
    ]
}

fn validate_web3_client_version(val: &Value, _peertest: &Peertest) {
    assert_eq!(val.as_str().unwrap(), "trin v0.1.0");
}

fn validate_discv5_node_info(val: &Value, _peertest: &Peertest) {
    let enr = val.get("enr").unwrap();
    assert!(enr.is_string());
    assert!(enr.as_str().unwrap().contains("enr:"));
    assert!(val.get("nodeId").unwrap().is_string());
}

fn validate_discv5_routing_table_info(val: &Value, _peertest: &Peertest) {
    let local_key = val.get("localKey").unwrap();
    assert!(local_key.is_string());
    assert!(local_key.as_str().unwrap().contains("0x"));
    assert!(val.get("buckets").unwrap().is_array());
}

fn validate_portal_history_radius(result: &Value, _peertest: &Peertest) {
    assert_eq!(result.as_str().unwrap(), DATA_RADIUS);
}

fn validate_portal_state_radius(result: &Value, _peertest: &Peertest) {
    assert_eq!(result.as_str().unwrap(), DATA_RADIUS);
}

fn validate_portal_history_ping(result: &Value, _peertest: &Peertest) {
    assert_eq!(
        result.get("dataRadius").unwrap().as_str().unwrap(),
        DATA_RADIUS
    );
    assert_eq!(
        result.get("enrSeq").unwrap().as_str().unwrap(),
        ENR_SEQ.to_string()
    );
}

fn validate_portal_state_ping(result: &Value, _peertest: &Peertest) {
    assert_eq!(
        result.get("dataRadius").unwrap().as_str().unwrap(),
        DATA_RADIUS
    );
    assert_eq!(
        result.get("enrSeq").unwrap().as_str().unwrap(),
        ENR_SEQ.to_string()
    );
}

fn validate_portal_find_nodes(result: &Value, peertest: &Peertest) {
    let nodes = NodesParams::try_from(result).unwrap();
    assert_eq!(nodes.total, 1u8);
    assert!(nodes.enrs.contains(&peertest.nodes[0].enr));
}

fn validate_portal_find_nodes_zero_distance(result: &Value, peertest: &Peertest) {
    let nodes = NodesParams::try_from(result).unwrap();
    assert_eq!(nodes.total, 1u8);
    assert!(nodes.enrs.contains(&peertest.bootnode.enr));
}

fn validate_portal_store(result: &Value, _peertest: &Peertest) {
    assert_eq!(result.as_str().unwrap(), "true");
}

fn validate_portal_store_with_invalid_content_key(result: &Value, _peertest: &Peertest) {
    assert!(result
        .as_str()
        .unwrap()
        .contains("Unable to decode content_key"));
}

#[cfg(unix)]
fn get_ipc_stream(ipc_path: &str) -> unix::net::UnixStream {
    unix::net::UnixStream::connect(ipc_path).unwrap()
}

#[cfg(windows)]
fn get_ipc_stream(ipc_path: &str) -> uds_windows::UnixStream {
    uds_windows::UnixStream::connect(ipc_path).unwrap()
}

pub fn make_ipc_request(ipc_path: &str, request: &JsonRpcRequest) -> anyhow::Result<Value> {
    let mut stream = get_ipc_stream(ipc_path);
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("Couldn't set read timeout");

    let json_request: Value = serde_json::from_str(&request.to_jsonrpc()).unwrap();
    let data = serde_json::to_vec(&json_request).unwrap();
    stream.write_all(&data).unwrap();
    stream.flush().unwrap();
    let deser = serde_json::Deserializer::from_reader(stream);
    let next_obj = deser.into_iter::<Value>().next();
    let response_obj = match next_obj {
        Some(val) => val,
        None => return Err(anyhow!("Empty JsonRpc response")),
    };
    get_response_result(response_obj)
}

pub async fn make_http_request(
    http_address: &str,
    request: &JsonRpcRequest,
) -> Result<Value, serde_json::Error> {
    let client = Client::new();
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{}", http_address))
        .header("content-type", "application/json")
        .body(Body::from(request.to_jsonrpc()))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
    serde_json::from_slice(&body)
}

pub fn get_enode(ipc_path: &str) -> anyhow::Result<SszEnr> {
    let info_request = JsonRpcRequest {
        method: "discv5_nodeInfo".to_string(),
        id: 1,
        params: Params::None,
    };
    let result = make_ipc_request(ipc_path, &info_request).map_err(|jsonerr| {
        anyhow!(
            "Error while trying to get enode for client at ipc_path {ipc_path:?} endpoint: {jsonerr:?}"
        )
    })?;
    match result.get("enr") {
        Some(val) => match SszEnr::try_from(val) {
            Ok(enr) => Ok(enr),
            Err(msg) => Err(anyhow!("Reported ENR value is an invalid enr: {msg:?}")),
        },
        None => Err(anyhow!("'enr' field not found in nodeInfo response")),
    }
}

#[allow(clippy::never_loop)]
pub async fn test_jsonrpc_endpoints_over_ipc(peertest_config: PeertestConfig, peertest: &Peertest) {
    info!("Testing IPC path: {}", peertest_config.target_ipc_path);
    for test in all_tests(peertest) {
        info!("Testing IPC method: {:?}", test.request.method);
        let response = make_ipc_request(&peertest_config.target_ipc_path, &test.request);
        match response {
            Ok(val) => test.validate(&val, peertest),
            Err(msg) => panic!(
                "Jsonrpc error for {:?} endpoint ('os error 11' means timeout): {:?}",
                test.request.method, msg
            ),
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
    peertest: &Peertest,
) {
    for test in all_tests(peertest) {
        info!("Testing over HTTP: {:?}", test.request.method);
        let response = make_http_request(&peertest_config.target_http_address, &test.request).await;
        match get_response_result(response) {
            Ok(result) => test.validate(&result, peertest),
            Err(msg) => panic!(
                "Jsonrpc error for {:?} endpoint: {:?}",
                test.request.method, msg
            ),
        }
    }
}
