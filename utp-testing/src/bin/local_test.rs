use std::net::SocketAddr;
use trin_core::portalnet::types::messages::ProtocolId;
use utp_testing::run_test_app;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let client_port = 9002;
    let client_external_addr = SocketAddr::from(([127, 0, 0, 1], client_port));
    let mut client = run_test_app(client_port, client_external_addr).await;

    let server_port = 9003;
    let server_external_addr = SocketAddr::from(([127, 0, 0, 1], server_port));

    let server = run_test_app(server_port, server_external_addr).await;

    let server_enr = server.discovery.local_enr();

    let connection_id = 66;
    let payload = vec![6; 2000];

    client
        .discovery
        .send_talk_req(server_enr.clone(), ProtocolId::History, vec![])
        .await
        .unwrap();

    server
        .prepare_to_receive(client.discovery.discv5.local_enr(), connection_id)
        .await;

    client
        .send_utp_request(connection_id, payload, server_enr)
        .await;

    tokio::signal::ctrl_c()
        .await
        .expect("failed to pause until ctrl-c");
}
