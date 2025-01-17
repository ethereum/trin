#![cfg(unix)]
/// Test that a 3rd-party web3 client can understand our JSON-RPC API
use std::fs;
use std::net::{IpAddr, Ipv4Addr};

use alloy::{
    primitives::U256,
    providers::{IpcConnect, Provider, ProviderBuilder, RootProvider},
    pubsub::PubSubFrontend,
    rpc::{
        client::ClientBuilder,
        types::{BlockNumberOrTag, BlockTransactions, BlockTransactionsKind, Header as RpcHeader},
    },
    transports::RpcError,
};
use ethportal_api::{
    types::execution::{block_body::BlockBody, header_with_proof::HeaderWithProof},
    utils::bytes::{hex_decode, hex_encode},
    ContentValue, Header, HistoryContentKey, HistoryContentValue, HistoryNetworkApiClient,
};
use jsonrpsee::async_client::Client;
use portalnet::constants::{DEFAULT_WEB3_HTTP_ADDRESS, DEFAULT_WEB3_IPC_PATH};
use rpc::RpcServerHandle;
use serde_yaml::Value;
use serial_test::serial;
use ssz::Decode;

mod utils;
use trin::cli::TrinConfig;
use url::Url;
use utils::init_tracing;

async fn setup_web3_server() -> (RpcServerHandle, RootProvider<PubSubFrontend>, Client) {
    init_tracing();

    let test_ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    // Use an uncommon port for the peertest to avoid clashes.
    let test_discovery_port = 8999;
    let external_addr = format!("{test_ip_addr}:{test_discovery_port}");

    // Run a client, to be tested
    let trin_config = TrinConfig::new_from([
        "trin",
        "--external-address",
        external_addr.as_str(),
        "--web3-ipc-path",
        DEFAULT_WEB3_IPC_PATH,
        "--ephemeral",
        "--discovery-port",
        &test_discovery_port.to_string(),
        "--bootnodes",
        "none",
    ])
    .unwrap();

    let web3_server = trin::run_trin(trin_config).await.unwrap();
    let ipc = IpcConnect::new(DEFAULT_WEB3_IPC_PATH.to_string());
    let web3_client = ProviderBuilder::new().on_ipc(ipc).await.unwrap();

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

    let (hwp, body) = get_full_block();
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
        .get_block_by_number(block_number.into(), /* hydrate= */ false)
        .await
        .expect("request to get block failed")
        .expect("specified block not found");

    assert_header(&block.header, &hwp.header);
    assert_eq!(block.size, Some(U256::from(37890)));
    assert_eq!(block.transactions.len(), body.transactions().len());
    assert!(block.uncles.is_empty());
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
        "0xd06a110de42d674a84b2091cbd85ef514fb4e903f9a80dd7b640c48365a1a832"
    );
    // Last tx
    assert_eq!(
        hex_encode(hashes[84]),
        "0x27e9e8fb3745d990c7d775268539fa17bbf06255e24a882c3153bf3b513ced9e"
    );
    // Legacy block
    assert_eq!(
        hex_encode(hashes[5]),
        "0x2f678341f550f7073a514c4b34f09824119f31dfbe7cc73ffccb21b7a2ba5710"
    );

    web3_server.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_eth_get_block_by_number_hydrated() {
    let (web3_server, web3_client, native_client) = setup_web3_server().await;

    let (hwp, _body) = get_full_block();
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
        .get_block_by_number(block_number.into(), /* hydrate= */ true)
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
        .get_block_by_number(BlockNumberOrTag::Latest, /* hydrate= */ false)
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

    let (hwp, body) = get_full_block();
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
    assert_eq!(block.size, Some(U256::from(37890)));
    assert_eq!(block.transactions.len(), body.transactions().len());
    assert!(block.uncles.is_empty());
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
        "0xd06a110de42d674a84b2091cbd85ef514fb4e903f9a80dd7b640c48365a1a832"
    );
    // Last tx
    assert_eq!(
        hex_encode(hashes[84]),
        "0x27e9e8fb3745d990c7d775268539fa17bbf06255e24a882c3153bf3b513ced9e"
    );
    // Legacy block
    assert_eq!(
        hex_encode(hashes[5]),
        "0x2f678341f550f7073a514c4b34f09824119f31dfbe7cc73ffccb21b7a2ba5710"
    );

    web3_server.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_eth_get_block_by_hash_hydrated() {
    let (web3_server, web3_client, native_client) = setup_web3_server().await;

    let (hwp, _body) = get_full_block();
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
    assert_eq!(actual.nonce, expected.nonce);
    assert_eq!(actual.uncles_hash, expected.uncles_hash);
    assert_eq!(actual.logs_bloom, expected.logs_bloom);
    assert_eq!(actual.miner, expected.author);
    assert_eq!(actual.state_root, expected.state_root);
    assert_eq!(actual.transactions_root, expected.transactions_root);
    assert_eq!(actual.receipts_root, expected.receipts_root);
    assert_eq!(actual.extra_data, expected.extra_data);
    assert_eq!(actual.mix_hash, expected.mix_hash);
    assert_eq!(actual.gas_used, expected.gas_used.to::<u64>());
    assert_eq!(actual.gas_limit, expected.gas_limit.to::<u64>());
    assert_eq!(actual.difficulty, expected.difficulty);
    assert_eq!(actual.timestamp, expected.timestamp);
}

fn get_full_block() -> (HeaderWithProof, BlockBody) {
    let file = fs::read_to_string("../../crates/validation/src/assets/hive/blocks.yaml").unwrap();
    let value: Value = serde_yaml::from_str(&file).unwrap();
    let all_blocks = value.as_sequence().unwrap();
    let post_shanghai = all_blocks.last().unwrap();
    // Why assert the block number? With the current yaml structure, appending a new block into the
    // yaml file would cause this function to return a different block. This assertion catches the
    // problem early.
    assert_eq!(post_shanghai["number"], 17510000);

    // header
    let ssz_header = get_ssz_contents(post_shanghai, "header");
    let hwp = HeaderWithProof::from_ssz_bytes(&ssz_header).unwrap();

    // body
    let ssz_body = get_ssz_contents(post_shanghai, "body");
    let body = BlockBody::from_ssz_bytes(&ssz_body).unwrap();

    (hwp, body)
}

// Panic if content is missing, since we're in a test
fn get_ssz_contents(value: &Value, field: &str) -> Vec<u8> {
    let content_pair = value.get(field).unwrap().as_mapping().unwrap();
    let hex_encoded = content_pair.get("content_value").unwrap().as_str().unwrap();
    hex_decode(hex_encoded).unwrap()
}
