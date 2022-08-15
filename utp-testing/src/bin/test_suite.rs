use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClientBuilder;
use jsonrpsee::rpc_params;
use log::info;
use std::time::Duration;

const SERVER_ADDR: &str = "193.167.100.100:9041";
const CLIENT_ADDR: &str = "193.167.0.100:9042";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let client_url = format!("http://{}", CLIENT_ADDR);
    let client_rpc = HttpClientBuilder::default().build(client_url)?;
    let client_enr: String = client_rpc.request("local_enr", None).await.unwrap();
    info!("Client Enr: {client_enr}");

    let server_url = format!("http://{}", SERVER_ADDR);
    let server_rpc = HttpClientBuilder::default().build(server_url)?;
    let server_enr: String = server_rpc.request("local_enr", None).await.unwrap();
    info!("Server Enr: {server_enr}");

    // Send talk request from client to server to establish discv5 session
    let params = rpc_params!(server_enr.clone());
    let response: String = client_rpc.request("talk_request", params).await.unwrap();
    assert_eq!(response, "OK");

    let connection_id = 66;

    let params = rpc_params!(client_enr, connection_id);
    let response: String = server_rpc.request("prepare_to_recv", params).await.unwrap();
    assert_eq!(response, "OK");

    let payload = vec![6; 1000];

    let params = rpc_params!(server_enr, connection_id, payload);
    let response: String = client_rpc
        .request("send_utp_payload", params)
        .await
        .unwrap();

    assert_eq!(response, "OK");

    tokio::time::sleep(Duration::from_secs(1)).await;

    Ok(())
}
