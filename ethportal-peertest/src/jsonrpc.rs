#[cfg(unix)]
use std::os::unix;
use std::{io::prelude::*, panic, time::Duration};

use anyhow::anyhow;
use hyper::{self, Body, Client, Method, Request};
use serde_json::{self, json, Value};
use ssz::Encode;
use tracing::{error, info};

use crate::{cli::PeertestConfig, Peertest};
use trin_core::utils::bytes::hex_encode;
use trin_core::{
    jsonrpc::types::{NodesParams, Params},
    portalnet::types::{distance::Distance, messages::SszEnr},
};

/// Default data radius value
const DATA_RADIUS: Distance = Distance::MAX;
/// Default enr seq value
const ENR_SEQ: &str = "1";
/// History HeaderWithProof content key & value
/// Block #1000010
pub const HISTORY_CONTENT_KEY: &str =
    "0x006251d65b8a8668efabe2f89c96a5b6332d83b3bbe585089ea6b2ab9b6754f5e9";
pub const HISTORY_CONTENT_VALUE: &str =
"0x0800000023020000f90218a00409be8253ad6ac0eb2056bc94194c6ccb83c74f4292c40c82e2dc8203bdc759a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942a65aca4d5fc5b5c859090a6c34d164135398226a0afbf9bfd23008e8df44a83bb51ade45b993b3253fbce69cf7cec5d628eca6d45a0a7120e4bd136c0b6bdb0fa4990649f8c34d10d180dbd5ad6d03502ae92d32308a0d78aa953fedc7f7c112b2686d0b2b7e37eba716dd1f5d74ef3c8a37005f35215b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000004000000000000000000040000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000860b69dd9d66ce830f424a832fefd88303a68c8456bfb4e398d783010303844765746887676f312e352e31856c696e7578a0e962efb883f91286e4fc6fd12989a70f24c174bd087f472528137c4134af0a1a88e857c5acc15dd82701cead98e305c70563000000000000000000000000000000000000000000000000be1b4a7a57f5316eea09c5e3e349141c46c1cb43664a815d28644cd74f282ca122360456d89447c0d586a8f5490922ea86b20e056879d64d87d104c14c0e594a6d800f67f5331ee2e511dc20e169c644b3df0f4c6b7c1717fc29d4844050b74044b506bf91edd14825aaec4f36fc5ad97b9eed9773aa2df15f80dff21eb668e24d61c29c3fda0fb425078a0479c5ea375ff95ad7780d0cdc87012009fd4a3dd003b06c7a28d6188e6be50ac544548cc7e3ee6cd07a8129f5c6d4d494b62ee8d96d26d0875bc87b56be0bf3e45846c0e3773abfccc239fdab29640b4e2aef297efcc6cb89b00a2566221cb4197ece3f66c24ea89969bd16265a74910aaf08d775116191117416b8799d0984f452a6fba19623442a7f199ef1627f1ae7295963a67db5534a292f98edbfb419ed85756abe76cd2d2bff8eb9b848b1e7b80b8274bbc469a36dce58b48ae57be6312bca843463ac45c54122a9f3fa9dca124b0fd50bce300708549c77b81b031278b9d193464f5e4b14769f6018055a457a577c508e811bcf55b297df3509f3db7e66ec68451e25acfbf935200e246f71e3c48240d00020000000000000000000000000000000000000000000000000000000000000";

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
                method: "portal_historyPing".to_string(),
                id: 6,
                params: Params::Array(vec![
                    Value::String(peertest.bootnode.enr.to_base64()),
                    json!(*DATA_RADIUS),
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
        Test::new(
            JsonRpcRequest {
                method: "portal_historyStore".to_string(),
                id: 11,
                params: Params::Array(vec![
                    Value::String(HISTORY_CONTENT_KEY.to_string()),
                    Value::String(HISTORY_CONTENT_VALUE.to_string()),
                ]),
            },
            validate_portal_store,
        ),
        Test::new(
            JsonRpcRequest {
                method: "portal_historyRoutingTableInfo".to_string(),
                id: 13,
                params: Params::None,
            },
            validate_portal_routing_table_info,
        ),
        Test::new(
            JsonRpcRequest {
                method: "portal_historyLocalContent".to_string(),
                id: 15,
                params: Params::Array(vec![Value::String(
                    "0x00cb5cab7266694daa0d28cbf40496c08dd30bf732c41e0455e7ad389c10d79f4f"
                        .to_string(),
                )]),
            },
            validate_portal_local_content,
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
    let local_key = val.get("localNodeId").unwrap();
    assert!(local_key.is_string());
    assert!(local_key.as_str().unwrap().contains("0x"));
    assert!(val.get("buckets").unwrap().is_array());
}

fn validate_portal_history_radius(result: &Value, _peertest: &Peertest) {
    assert_eq!(result.as_str().unwrap(), DATA_RADIUS.to_string());
}

fn validate_portal_history_ping(result: &Value, _peertest: &Peertest) {
    assert_eq!(
        result.get("dataRadius").unwrap().as_str().unwrap(),
        hex_encode(DATA_RADIUS.as_ssz_bytes())
    );
    assert_eq!(
        result.get("enrSeq").unwrap().as_u64().unwrap().to_string(),
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
    assert!(result.as_bool().unwrap());
}

fn validate_portal_routing_table_info(result: &Value, _peertest: &Peertest) {
    assert!(result.get("buckets").unwrap().is_object());
    assert!(result.get("numBuckets").unwrap().is_u64());
    assert!(result.get("numNodes").unwrap().is_u64());
    assert!(result.get("numConnected").unwrap().is_u64());
}

pub fn validate_portal_offer(result: &Value, _peertest: &Peertest) {
    // Expect u64 connection id
    let connection_id = result
        .get("connectionId")
        .unwrap()
        .as_u64()
        .unwrap()
        .to_string();
    assert!(connection_id.parse::<u64>().is_ok());
    // Should accept the requested content
    assert_eq!(result.get("contentKeys").unwrap().as_str(), Some("0x03"))
}

pub fn validate_portal_local_content(result: &Value, _peertest: &Peertest) {
    assert_eq!(result.as_str().unwrap(), "0x0");
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
        .set_read_timeout(Some(Duration::from_millis(1500)))
        .expect("Couldn't set read timeout");

    let json_request: Value = serde_json::from_str(&request.to_jsonrpc()).unwrap();
    let data = serde_json::to_vec(&json_request).unwrap();
    stream.write_all(&data).unwrap();
    stream.flush().unwrap();
    let deser = serde_json::Deserializer::from_reader(stream);
    let next_obj = deser.into_iter::<Value>().next();
    let response_obj = next_obj.ok_or_else(|| anyhow!("Empty JsonRpc response"))?;
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
            Err(msg) => {
                error!(
                    "Jsonrpc error for {:?} endpoint ('os error 11' means timeout): {:?}",
                    test.request.method, msg
                );
                panic!("Must always get jsonrpc success");
            }
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
