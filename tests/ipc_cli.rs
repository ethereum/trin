mod common;
use common::JsonResponse;
use serde_json;
use serial_test::serial;
use std::ffi::OsStr;
use std::io::prelude::*;
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::{thread, time};
use tempfile::tempdir;

#[test]
#[serial]
fn test_client_version() {
    let tmpdir = tempdir().unwrap();
    let tmp = tmpdir.path().join("trin-jsonrpc.ipc");
    let path = tmp.into_os_string();

    let bin_path = OsStr::new("./target/debug/trin");
    let mut handle = Command::new(bin_path)
        .arg("-p")
        .arg("ipc")
        .arg("-i")
        .arg(&path)
        .spawn()
        .expect("trin subprocess failed to launch");

    // sleep for a second to allow subprocess to start
    let one_second = time::Duration::from_secs(1);
    thread::sleep(one_second);

    let mut stream = UnixStream::connect(path).unwrap();
    let request = br#"{"jsonrpc":"2.0","id":"1","method":"web3_clientVersion"}"#;
    stream.write_all(request).unwrap();

    let mut buf = [0; 1024];
    stream.read(&mut buf).unwrap();

    handle.kill().unwrap();
    tmpdir.close().unwrap();

    let raw_response = std::str::from_utf8(&buf).unwrap();
    let formatted_response = raw_response.trim_end_matches("\u{0}");
    let response: JsonResponse = serde_json::from_str(&formatted_response).unwrap();
    assert_eq!(response.jsonrpc, "2.0");
    assert_eq!(response.id, "1");
    assert_eq!(response.result, "trin 0.0.1-alpha");
}

#[test]
#[serial]
fn test_block_number() {
    let tmpdir = tempdir().unwrap();
    let tmp = tmpdir.path().join("trin-jsonrpc.ipc");
    let path = tmp.into_os_string();

    let bin_path = OsStr::new("./target/debug/trin");
    let mut handle = Command::new(bin_path)
        .arg("-p")
        .arg("ipc")
        .arg("-i")
        .arg(&path)
        .spawn()
        .expect("trin subprocess failed to launch");

    // sleep for a second to allow subprocess to start
    let one_second = time::Duration::from_secs(1);
    thread::sleep(one_second);

    let mut stream = UnixStream::connect(path).unwrap();
    let request = br#"{"jsonrpc":"2.0","id":"1","method":"eth_blockNumber"}"#;
    stream.write_all(request).unwrap();

    let mut buf = [0; 1024];
    stream.read(&mut buf).unwrap();
    handle.kill().unwrap();
    tmpdir.close().unwrap();
    let raw_response = std::str::from_utf8(&buf).unwrap();
    let formatted_response = raw_response.trim_end_matches("\u{0}");
    let response: JsonResponse = serde_json::from_str(&formatted_response).unwrap();
    assert_eq!(response.jsonrpc, "2.0");
    assert_eq!(response.id, "1");
    assert!(response.result.contains("0x"));
}
