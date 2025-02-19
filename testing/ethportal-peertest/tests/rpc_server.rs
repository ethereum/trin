#![cfg(unix)]
/// Test that a 3rd-party web3 client can understand our JSON-RPC API
use std::net::{IpAddr, Ipv4Addr};

use alloy::{
    primitives::{Bytes, U256},
    providers::{DynProvider, IpcConnect, Provider, ProviderBuilder},
    rpc::{
        client::ClientBuilder,
        types::{BlockNumberOrTag, BlockTransactions, BlockTransactionsKind, Header as RpcHeader},
    },
    transports::RpcError,
};
use ethportal_api::{
    types::execution::{block_body::BlockBody, header_with_proof_new::HeaderWithProof},
    utils::bytes::hex_encode,
    version::APP_NAME,
    ContentValue, Header, HistoryContentKey, HistoryContentValue, HistoryNetworkApiClient,
};
use jsonrpsee::async_client::Client;
use portalnet::constants::{DEFAULT_WEB3_HTTP_ADDRESS, DEFAULT_WEB3_IPC_PATH};
use rpc::RpcServerHandle;
use serde::Deserialize;
use serde_yaml::Value;
use serial_test::serial;
use ssz::Decode;

mod utils;
use trin::cli::TrinConfig;
use trin_utils::submodules::read_portal_spec_tests_file;
use url::Url;
use utils::init_tracing;

async fn setup_web3_server() -> (RpcServerHandle, DynProvider, Client) {
    init_tracing();

    let test_ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    // Use an uncommon port for the peertest to avoid clashes.
    let test_discovery_port = 8999;
    let external_addr = format!("{test_ip_addr}:{test_discovery_port}");

    // Run a client, to be tested
    let trin_config = TrinConfig::new_from([
        APP_NAME,
        "--external-address",
        external_addr.as_str(),
        "--web3-ipc-path",
        DEFAULT_WEB3_IPC_PATH,
        "--ephemeral",
        "--discovery-port",
        &test_discovery_port.to_string(),
        "--bootnodes",
        "none",
        "--max-radius",
        "100",
    ])
    .unwrap();

    let web3_server = trin::run_trin(trin_config).await.unwrap();
    let ipc = IpcConnect::new(DEFAULT_WEB3_IPC_PATH.to_string());
    let web3_client = DynProvider::new(ProviderBuilder::new().on_ipc(ipc).await.unwrap());

    // Tests that use native client belong in tests/self_peertest.rs, but it is convenient to use
    // the native client to populate content in the server's database.
    let native_client = reth_ipc::client::IpcClientBuilder::default()
        .build(DEFAULT_WEB3_IPC_PATH)
        .await
        .unwrap();
    (web3_server, web3_client, native_client)
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_batch_call() {
    init_tracing();

    let test_ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let test_discovery_port = 8999;
    let external_addr = format!("{test_ip_addr}:{test_discovery_port}");

    let trin_config = TrinConfig::new_from([
        "trin",
        "--external-address",
        external_addr.as_str(),
        "--web3-transport",
        "http",
        "--ephemeral",
        "--discovery-port",
        &test_discovery_port.to_string(),
        "--bootnodes",
        "none",
        "--max-radius",
        "100",
    ])
    .unwrap();

    let web3_server = trin::run_trin(trin_config).await.unwrap();

    let url = Url::parse(DEFAULT_WEB3_HTTP_ADDRESS).unwrap();
    let client = ClientBuilder::default().http(url);

    let mut batch = client.new_batch();

    let client_version_future = batch
        .add_call::<(), serde_json::Value>("web3_clientVersion", &())
        .unwrap();
    let node_info_future = batch
        .add_call::<(), serde_json::Value>("discv5_nodeInfo", &())
        .unwrap();

    batch.send().await.unwrap();
    client_version_future.await.unwrap();
    node_info_future.await.unwrap();

    web3_server.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_eth_chain_id() {
    let (web3_server, web3_client, _) = setup_web3_server().await;
    let chain_id = web3_client.get_chain_id().await.unwrap();
    web3_server.stop().unwrap();
    // For now, the chain ID is always 1 -- Portal only supports mainnet Ethereum
    // Intentionally testing against the magic number 1 so that a buggy constant value will fail
    assert_eq!(chain_id, 1);
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_eth_get_block_by_number() {
    let (web3_server, web3_client, native_client) = setup_web3_server().await;

    let (hwp, body) = get_full_block_14764013();
    let block_number = hwp.header.number;

    // Store header with proof in server
    assert!(native_client
        .store(
            HistoryContentKey::new_block_header_by_number(block_number),
            HistoryContentValue::BlockHeaderWithProof(hwp.clone()).encode(),
        )
        .await
        .unwrap());

    // Store block in server
    assert!(native_client
        .store(
            HistoryContentKey::new_block_body(hwp.header.hash()),
            HistoryContentValue::BlockBody(body.clone()).encode(),
        )
        .await
        .unwrap());

    // The meat of the test is here:
    // Retrieve block over json-rpc
    let block = web3_client
        .get_block_by_number(block_number.into(), BlockTransactionsKind::Hashes)
        .await
        .expect("request to get block failed")
        .expect("specified block not found");

    assert_header(&block.header, &hwp.header);
    assert_eq!(block.header.size, Some(U256::from(8086)));
    assert_eq!(block.transactions.len(), body.transactions().len());
    assert_eq!(block.uncles.len(), 1);
    assert_eq!(
        block.withdrawals.unwrap_or_default().len(),
        body.withdrawals().unwrap_or_default().len()
    );

    let BlockTransactions::Hashes(hashes) = block.transactions else {
        panic!("expected hashes")
    };
    // Spot check a few transaction hashes:
    // First tx
    assert_eq!(
        hex_encode(hashes[0]),
        "0x163dae461ab32787eaecdad0748c9cf5fe0a22b443bc694efae9b80e319d9559"
    );
    // Last tx
    assert_eq!(
        hex_encode(hashes[18]),
        "0x654e68914918cc400de261aaa40d95bcb8a9542756113771accfae0af09c451f"
    );

    web3_server.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_eth_get_block_by_number_hydrated() {
    let (web3_server, web3_client, native_client) = setup_web3_server().await;

    let (hwp, _body) = get_full_block_14764013();
    let block_number = hwp.header.number;

    // Store header with proof in server
    assert!(native_client
        .store(
            HistoryContentKey::new_block_header_by_number(block_number),
            HistoryContentValue::BlockHeaderWithProof(hwp.clone()).encode(),
        )
        .await
        .unwrap());

    let response = web3_client
        .get_block_by_number(block_number.into(), BlockTransactionsKind::Full)
        .await;

    let err = match response {
        Err(RpcError::ErrorResp(err)) => err,
        _ => panic!("Unexpected response: {response:?}"),
    };
    assert_eq!(
        err.message, "replying with all transaction bodies is not supported yet",
        "Unexpected error: {err}"
    );

    web3_server.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_eth_get_block_by_tag() {
    let (web3_server, web3_client, _native_client) = setup_web3_server().await;

    let response = web3_client
        .get_block_by_number(BlockNumberOrTag::Latest, BlockTransactionsKind::Hashes)
        .await;

    let err = match response {
        Err(RpcError::ErrorResp(err)) => err,
        _ => panic!("Unexpected response: {response:?}"),
    };
    assert_eq!(
        err.message, "Block tag is not supported yet.",
        "Unexpected error: {err}"
    );

    web3_server.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_eth_get_block_by_hash() {
    let (web3_server, web3_client, native_client) = setup_web3_server().await;

    let (hwp, body) = get_full_block_14764013();
    let block_hash = hwp.header.hash();

    // Store header with proof in server
    assert!(native_client
        .store(
            HistoryContentKey::new_block_header_by_hash(block_hash),
            HistoryContentValue::BlockHeaderWithProof(hwp.clone()).encode(),
        )
        .await
        .unwrap());

    // Store block in server
    assert!(native_client
        .store(
            HistoryContentKey::new_block_body(block_hash),
            HistoryContentValue::BlockBody(body.clone()).encode(),
        )
        .await
        .unwrap());

    // The meat of the test is here:
    // Retrieve block over json-rpc
    let block = web3_client
        .get_block_by_hash(block_hash, BlockTransactionsKind::Hashes)
        .await
        .expect("request to get block failed")
        .expect("specified block not found");

    assert_header(&block.header, &hwp.header);
    assert_eq!(block.header.size, Some(U256::from(8086)));
    assert_eq!(block.transactions.len(), body.transactions().len());
    assert_eq!(block.uncles.len(), 1);
    assert_eq!(
        block.withdrawals.unwrap_or_default().len(),
        body.withdrawals().unwrap_or_default().len()
    );

    let BlockTransactions::Hashes(hashes) = block.transactions else {
        panic!("expected hashes")
    };
    // Spot check a few transaction hashes:
    // First tx
    assert_eq!(
        hex_encode(hashes[0]),
        "0x163dae461ab32787eaecdad0748c9cf5fe0a22b443bc694efae9b80e319d9559"
    );
    // Last tx
    assert_eq!(
        hex_encode(hashes[18]),
        "0x654e68914918cc400de261aaa40d95bcb8a9542756113771accfae0af09c451f"
    );

    web3_server.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_eth_get_block_by_hash_hydrated() {
    let (web3_server, web3_client, native_client) = setup_web3_server().await;

    let (hwp, _body) = get_full_block_14764013();
    let block_hash = hwp.header.hash();

    // Store header with proof in server
    assert!(native_client
        .store(
            HistoryContentKey::new_block_header_by_hash(block_hash),
            HistoryContentValue::BlockHeaderWithProof(hwp.clone()).encode(),
        )
        .await
        .unwrap());

    let response = web3_client
        .get_block_by_hash(block_hash, BlockTransactionsKind::Full)
        .await;

    let err = match response {
        Err(RpcError::ErrorResp(err)) => err,
        _ => panic!("Unexpected response: {response:?}"),
    };
    assert_eq!(
        err.message, "replying with all transaction bodies is not supported yet",
        "Unexpected error: {err}"
    );

    web3_server.stop().unwrap();
}

fn assert_header(actual: &RpcHeader, expected: &Header) {
    assert_eq!(actual.number, expected.number);
    assert_eq!(actual.hash, expected.hash());
    assert_eq!(actual.parent_hash, expected.parent_hash);
    assert_eq!(Some(actual.nonce), expected.nonce);
    assert_eq!(actual.ommers_hash, expected.uncles_hash);
    assert_eq!(actual.logs_bloom, expected.logs_bloom);
    assert_eq!(actual.beneficiary, expected.author);
    assert_eq!(actual.state_root, expected.state_root);
    assert_eq!(actual.transactions_root, expected.transactions_root);
    assert_eq!(actual.receipts_root, expected.receipts_root);
    assert_eq!(actual.extra_data, expected.extra_data);
    assert_eq!(Some(actual.mix_hash), expected.mix_hash);
    assert_eq!(actual.gas_used, expected.gas_used.to::<u64>());
    assert_eq!(actual.gas_limit, expected.gas_limit.to::<u64>());
    assert_eq!(actual.difficulty, expected.difficulty);
    assert_eq!(actual.timestamp, expected.timestamp);
}

fn get_full_block_14764013() -> (HeaderWithProof, BlockBody) {
    let hwp_file =
        read_portal_spec_tests_file("tests/mainnet/history/headers_with_proof/14764013.yaml")
            .unwrap();
    let hwp = get_content_value::<HeaderWithProof>(&hwp_file);

    let body_file =
        read_portal_spec_tests_file("tests/mainnet/history/bodies/14764013.yaml").unwrap();
    let body = get_content_value::<BlockBody>(&body_file);

    (hwp, body)
}

fn get_content_value<T: Decode>(yaml_file: &str) -> T {
    let value: Value = serde_yaml::from_str(yaml_file).unwrap();
    let bytes = Bytes::deserialize(&value["content_value"]).unwrap();
    T::from_ssz_bytes(&bytes).unwrap()
}
