use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClientBuilder;
use jsonrpsee::rpc_params;
use log::info;
use std::net::SocketAddr;
use std::time::Duration;
use tracing_subscriber::util::SubscriberInitExt;
use utp_testing::run_test_app;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()?
        .add_directive("jsonrpsee[method_call{name = \"talk_request\"}]=trace".parse()?);
    tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(filter)
        .finish()
        .try_init()?;

    let client_port = 9002;
    let client_external_addr = SocketAddr::from(([127, 0, 0, 1], client_port));
    let (client_addr, client_enr, _client_handle) =
        run_test_app(client_port, client_external_addr, 35025)
            .await
            .unwrap();
    let url = format!("http://{}", client_addr);
    let client_rpc = HttpClientBuilder::default().build(url)?;

    let server_port = 9003;
    let server_external_addr = SocketAddr::from(([127, 0, 0, 1], server_port));
    let (server_addr, server_enr, _server_handle) =
        run_test_app(server_port, server_external_addr, 4365)
            .await
            .unwrap();
    let url = format!("http://{}", server_addr);
    let server_rpc = HttpClientBuilder::default().build(url)?;

    let params = rpc_params!(server_enr.to_base64());
    let response: String = client_rpc.request("talk_request", params).await.unwrap();

    info!("Response: {response:?}");

    let connection_id = 66;
    let payload = vec![6; 2000];

    let params = rpc_params!(client_enr.to_base64(), connection_id);
    let response: String = server_rpc.request("prepare_to_recv", params).await.unwrap();

    info!("Response: {response:?}");

    let params = rpc_params!(server_enr.to_base64(), connection_id, payload);
    let response: String = client_rpc
        .request("send_utp_payload", params)
        .await
        .unwrap();

    info!("Response: {response:?}");

    tokio::time::sleep(Duration::from_secs(1)).await;

    Ok(())
}
