mod common;
use common::JsonResponse;
use reqwest;
use serde_json;
use serial_test::serial;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::process::Command;
use std::{thread, time};

#[test]
#[serial]
fn test_client_version() {
    let bin_path = OsStr::new("./target/debug/trin");
    let mut handle = Command::new(bin_path)
        .spawn()
        .expect("trin subprocess failed to launch");

    let mut map = HashMap::new();
    map.insert("jsonrpc", "2.0");
    map.insert("id", "1");
    map.insert("method", "web3_clientVersion");

    // sleep for a second to allow subprocess to start
    let one_second = time::Duration::from_secs(1);
    thread::sleep(one_second);

    let client = reqwest::blocking::Client::new();
    let res = client.post("http://127.0.0.1:8545").json(&map).send();

    let response: JsonResponse = match res {
        Ok(val) => serde_json::from_str(&val.text().unwrap()).unwrap(),
        Err(msg) => {
            handle.kill().unwrap();
            panic!("Failed test, test_client_version: {}", msg);
        }
    };

    handle.kill().unwrap();
    assert_eq!(response.jsonrpc, "2.0");
    assert_eq!(response.id, "1");
    assert_eq!(response.result, "trin 0.0.1-alpha");
}

#[test]
#[serial]
fn test_block_number() {
    let bin_path = OsStr::new("./target/debug/trin");
    let mut handle = Command::new(bin_path)
        .spawn()
        .expect("trin subprocess failed to launch");

    let mut map = HashMap::new();
    map.insert("jsonrpc", "2.0");
    map.insert("id", "1");
    map.insert("method", "eth_blockNumber");

    let one_second = time::Duration::from_secs(1);
    thread::sleep(one_second);

    let client = reqwest::blocking::Client::new();
    let res = client.post("http://127.0.0.1:8545").json(&map).send();

    let response = match res {
        Ok(val) => val.text(),
        Err(msg) => {
            handle.kill().unwrap();
            panic!("test_block_number test failed: {}", msg);
        }
    };

    let response: JsonResponse = serde_json::from_str(&response.unwrap()).unwrap();
    handle.kill().unwrap();
    assert_eq!(response.jsonrpc, "2.0");
    assert_eq!(response.id, "1");
    assert!(response.result.contains("0x"));
}
