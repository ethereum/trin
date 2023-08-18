use clap::Parser;
use ethportal_api::jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use portal_bridge::beacon_bridge::BeaconBridge;
use portal_bridge::bridge::Bridge;
use portal_bridge::cli::BridgeConfig;
use portal_bridge::consensus_api::ConsensusApi;
use portal_bridge::pandaops::PandaOpsMiddleware;
use portal_bridge::types::NetworkKind;
use portal_bridge::utils::generate_spaced_private_keys;
use tokio::time::{sleep, Duration};
use trin_utils::log::init_tracing_logger;
use trin_validation::accumulator::MasterAccumulator;
use trin_validation::oracle::HeaderOracle;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing_logger();

    let bridge_config = BridgeConfig::parse();
    let private_keys = generate_spaced_private_keys(bridge_config.node_count);
    let mut handles = vec![];
    let mut http_addresses = vec![];
    for (i, key) in private_keys.into_iter().enumerate() {
        let web3_http_port = 8545 + i;
        let discovery_port = 9000 + i;
        let handle = bridge_config.client_type.build_handle(
            key,
            web3_http_port as u16,
            discovery_port as u16,
            bridge_config.clone(),
        );
        let web3_http_address = format!("http://127.0.0.1:{}", web3_http_port);
        http_addresses.push(web3_http_address);
        handles.push(handle);
    }
    sleep(Duration::from_secs(5)).await;

    let portal_clients: Result<Vec<HttpClient>, String> = http_addresses
        .iter()
        .map(|address| {
            HttpClientBuilder::default()
                .build(address)
                .map_err(|e| e.to_string())
        })
        .collect();

    let mut bridge_tasks = Vec::new();

    // Launch Beacon Network portal bridge
    if bridge_config.network.contains(&NetworkKind::Beacon) {
        let bridge_mode = bridge_config.mode.clone();
        let portal_clients = portal_clients.clone();
        let bridge_handle = tokio::spawn(async move {
            let pandaops_middleware = PandaOpsMiddleware::default();
            let consensus_api = ConsensusApi::new(pandaops_middleware);
            let beacon_bridge = BeaconBridge::new(
                consensus_api,
                bridge_mode,
                portal_clients.expect("Failed to create beacon JSON-RPC clients"),
            );

            beacon_bridge.launch().await;
        });

        bridge_tasks.push(bridge_handle);
    }

    // Launch History Network portal bridge
    if bridge_config.network.contains(&NetworkKind::History) {
        let bridge_handle = tokio::spawn(async move {
            let master_acc = MasterAccumulator::default();
            let header_oracle = HeaderOracle::new(master_acc);

            let bridge = Bridge::new(
                bridge_config.mode,
                portal_clients.expect("Failed to create history JSON-RPC clients"),
                header_oracle,
                bridge_config.epoch_acc_path,
            );

            bridge.launch().await;
        });

        bridge_tasks.push(bridge_handle);
    }

    futures::future::join_all(bridge_tasks).await;

    Ok(())
}
