use jsonrpsee::{core::client::ClientT, http_client::HttpClientBuilder, rpc_params};
use rand::{thread_rng, Rng};
use trin_utils::log::init_tracing_logger;

use std::time::Duration;

use ethportal_api::utils::bytes::hex_encode;

const SERVER_ADDR: &str = "193.167.100.100:9041";
const CLIENT_ADDR: &str = "193.167.0.100:9042";

/// Test suite for testing uTP protocol with network simulator
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing_logger();
    send_10k_bytes().await?;

    Ok(())
}

/// Send 10k bytes payload from client to server
async fn send_10k_bytes() -> anyhow::Result<()> {
    println!("Sending 10k bytes uTP payload from client to server...");
    let client_url = format!("http://{CLIENT_ADDR}");
    let client_rpc = HttpClientBuilder::default().build(client_url)?;
    let client_enr: String = client_rpc
        .request("local_enr", rpc_params![])
        .await
        .unwrap();

    let server_url = format!("http://{SERVER_ADDR}");
    let server_rpc = HttpClientBuilder::default().build(server_url)?;
    let server_enr: String = server_rpc
        .request("local_enr", rpc_params![])
        .await
        .unwrap();

    let client_cid_recv: u16 = thread_rng().gen();
    let client_cid_send = client_cid_recv.wrapping_add(1);

    // The server connection ID is the flipped client connection ID.
    let server_cid_recv = client_cid_send;
    let server_cid_send = client_cid_recv;

    // Add client enr to allowed server uTP connections
    let params = rpc_params!(client_enr, server_cid_send, server_cid_recv);
    let response: String = server_rpc.request("prepare_to_recv", params).await.unwrap();
    assert_eq!(response, "true");

    // Send uTP payload from client to server
    let payload: Vec<u8> = vec![thread_rng().gen(); 10_000];

    let params = rpc_params!(
        server_enr,
        client_cid_send,
        client_cid_recv,
        payload.clone()
    );
    let response: String = client_rpc
        .request("send_utp_payload", params)
        .await
        .unwrap();

    assert_eq!(response, "true");

    // Sleep to allow time for uTP transmission
    tokio::time::sleep(Duration::from_secs(16)).await;

    // Verify received uTP payload
    let utp_payload: String = server_rpc
        .request("get_utp_payload", rpc_params![])
        .await
        .unwrap();
    let expected_payload = hex_encode(payload);

    assert_eq!(expected_payload, utp_payload);

    println!("Sent 10k bytes uTP payload from client to server: OK");

    Ok(())
}
