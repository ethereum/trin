#![cfg(unix)]
/// Test that a 3rd-party web3 client can understand our JSON-RPC API
use std::fs;
use std::net::{IpAddr, Ipv4Addr};

use ethers::types::H160;
use ethers_core::types::{Bloom, U256};
use ethers_providers::*;
use jsonrpsee::async_client::Client;
use serde_yaml::Value;
use serial_test::serial;
use ssz::Decode;

use ethportal_api::{
    types::{
        cli::{TrinConfig, DEFAULT_WEB3_IPC_PATH},
        execution::{block_body::BlockBody, header_with_proof::HeaderWithProof},
    },
    utils::bytes::{hex_decode, hex_encode},
    HistoryContentKey, HistoryContentValue, HistoryNetworkApiClient,
};
use rpc::RpcServerHandle;

mod utils;
use utils::{init_tracing, u256_to_ethers_u256, u64_to_ethers_u256};

async fn setup_web3_server() -> (RpcServerHandle, Provider<Ipc>, Client) {
    init_tracing();

    let test_ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    // Use an uncommon port for the peertest to avoid clashes.
    let test_discovery_port = 8999;
    let external_addr = format!("{test_ip_addr}:{test_discovery_port}");

    // Run a client, to be tested
    let trin_config = TrinConfig::new_from(
        [
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
        ]
        .iter(),
    )
    .unwrap();

    let web3_server = trin::run_trin(trin_config).await.unwrap();
    let web3_client = Provider::connect_ipc(DEFAULT_WEB3_IPC_PATH).await.unwrap();
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
async fn test_eth_chain_id() {
    let (web3_server, web3_client, _) = setup_web3_server().await;
    let chain_id = web3_client.get_chainid().await.unwrap();
    web3_server.stop().unwrap();
    // For now, the chain ID is always 1 -- Portal only supports mainnet Ethereum
    // Intentionally testing against the magic number 1 so that a buggy constant value will fail
    assert_eq!(chain_id, U256::from(1));
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_eth_get_block_by_hash() {
    let (web3_server, web3_client, native_client) = setup_web3_server().await;

    let (hwp, body) = get_full_block();
    // Save values for later comparison
    let (
        block_number,
        block_hash,
        parent_hash,
        nonce,
        uncles_hash,
        logs_bloom,
        author,
        state_root,
        transactions_root,
        receipts_root,
        extra_data,
        mix_hash,
        gas_used,
        gas_limit,
        difficulty,
        timestamp,
    ) = (
        hwp.header.number.into(),
        hwp.header.hash(),
        hwp.header.parent_hash.0.into(),
        hwp.header.nonce.expect("nonce must be present").0.into(),
        hwp.header.uncles_hash.0.into(),
        Bloom::from(hwp.header.logs_bloom.into_array()),
        H160::from(hwp.header.author.into_array()),
        hwp.header.state_root.0.into(),
        hwp.header.transactions_root.0.into(),
        hwp.header.receipts_root.0.into(),
        hwp.header.extra_data.clone(),
        hwp.header.mix_hash.map(|h| h.0.into()),
        u256_to_ethers_u256(hwp.header.gas_used),
        u256_to_ethers_u256(hwp.header.gas_limit),
        u256_to_ethers_u256(hwp.header.difficulty),
        u64_to_ethers_u256(hwp.header.timestamp),
    );

    let BlockBody::Shanghai(shanghai_body) = body.clone() else {
        panic!("expected shanghai body")
    };

    // Store header with proof in server
    let content_key = HistoryContentKey::BlockHeaderWithProof(block_hash.into());
    let content_value = HistoryContentValue::BlockHeaderWithProof(hwp);
    let result = native_client
        .store(content_key, content_value)
        .await
        .unwrap();
    assert!(result);

    // Store block in server
    let content_key = HistoryContentKey::BlockBody(block_hash.into());
    let content_value = HistoryContentValue::BlockBody(body);
    let result = native_client
        .store(content_key, content_value)
        .await
        .unwrap();
    assert!(result);

    // The meat of the test is here:
    // Retrieve block over json-rpc
    let block_id = ethers_core::types::H256::from(&block_hash.0);
    let block = web3_client
        .get_block(block_id)
        .await
        .expect("request to get block failed")
        .expect("specified block not found");
    web3_server.stop().unwrap();

    let block_hash = block_hash.0.into();
    assert_eq!(block.number.expect("number must be present"), block_number);
    assert_eq!(block.hash.expect("hash must be present"), block_hash);
    assert_eq!(block.parent_hash, parent_hash);
    assert_eq!(block.nonce.expect("nonce must be present"), nonce);
    assert_eq!(block.uncles_hash, uncles_hash);
    assert_eq!(block.logs_bloom.expect("bloom must be present"), logs_bloom);
    assert_eq!(block.author.expect("block author must be present"), author);
    assert_eq!(block.state_root, state_root);
    assert_eq!(block.transactions_root, transactions_root);
    assert_eq!(block.receipts_root, receipts_root);
    assert_eq!(block.extra_data, extra_data);
    assert_eq!(block.mix_hash, mix_hash);
    assert_eq!(block.gas_used, gas_used);
    assert_eq!(block.gas_limit, gas_limit);
    assert_eq!(block.difficulty, difficulty);
    assert_eq!(block.timestamp, timestamp);
    assert_eq!(block.size, None);
    assert_eq!(block.transactions.len(), shanghai_body.txs.len());

    // Spot check a few transaction hashes:
    // First tx
    assert_eq!(
        hex_encode(block.transactions[0]),
        "0xd06a110de42d674a84b2091cbd85ef514fb4e903f9a80dd7b640c48365a1a832"
    );
    // Last tx
    assert_eq!(
        hex_encode(block.transactions[84]),
        "0x27e9e8fb3745d990c7d775268539fa17bbf06255e24a882c3153bf3b513ced9e"
    );
    // Legacy block
    assert_eq!(
        hex_encode(block.transactions[5]),
        "0x2f678341f550f7073a514c4b34f09824119f31dfbe7cc73ffccb21b7a2ba5710"
    );
}

fn get_full_block() -> (HeaderWithProof, BlockBody) {
    let file = fs::read_to_string("trin-validation/src/assets/hive/blocks.yaml").unwrap();
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
