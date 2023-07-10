use clap::Parser;
use ethportal_api::jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use portal_bridge::bridge::Bridge;
use portal_bridge::cli::BridgeConfig;
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
    let master_acc = MasterAccumulator::try_from_file("validation_assets/merge_macc.bin".into())?;
    let header_oracle = HeaderOracle::new(master_acc);

    let portal_clients: Result<Vec<HttpClient>, String> = http_addresses
        .iter()
        .map(|address| {
            HttpClientBuilder::default()
                .build(address)
                .map_err(|e| e.to_string())
        })
        .collect();
    let bridge = Bridge::new(
        bridge_config.mode,
        portal_clients?,
        header_oracle,
        bridge_config.epoch_acc_path,
    );

    bridge.launch().await;
    Ok(())
}
