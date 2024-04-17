use std::sync::Arc;

use clap::Parser;
use tokio::time::{sleep, Duration};
use tracing::Instrument;

use ethportal_api::jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use portal_bridge::{
    api::{consensus::ConsensusApi, execution::ExecutionApi},
    bridge::{beacon::BeaconBridge, era1::Era1Bridge, history::HistoryBridge},
    cli::BridgeConfig,
    types::{mode::BridgeMode, network::NetworkKind},
    utils::generate_spaced_private_keys,
};
use trin_utils::log::init_tracing_logger;
use trin_validation::{accumulator::MasterAccumulator, oracle::HeaderOracle};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing_logger();

    let bridge_config = BridgeConfig::parse();

    if let Some(addr) = bridge_config.metrics_url {
        prometheus_exporter::start(addr)?;
    }

    let private_keys =
        generate_spaced_private_keys(bridge_config.node_count, bridge_config.root_private_key);
    let mut handles = vec![];
    let mut http_addresses = vec![];
    for (i, key) in private_keys.into_iter().enumerate() {
        let web3_http_port = bridge_config.base_rpc_port + i as u16;
        let discovery_port = bridge_config.base_discovery_port + i as u16;
        let handle = bridge_config.client_type.build_handle(
            key,
            web3_http_port,
            discovery_port,
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
                // increase default timeout to allow for trace_gossip requests that can take a long
                // time
                .request_timeout(Duration::from_secs(120))
                .build(address)
                .map_err(|e| e.to_string())
        })
        .collect();

    let mut bridge_tasks = Vec::new();

    // Launch Beacon Network portal bridge
    if bridge_config.network.contains(&NetworkKind::Beacon) {
        let bridge_mode = bridge_config.mode.clone();
        let portal_clients = portal_clients
            .clone()
            .expect("Failed to create beacon JSON-RPC clients");
        let consensus_api = ConsensusApi::new(
            bridge_config.cl_provider,
            bridge_config.cl_provider_fallback,
        )
        .await?;
        let bridge_handle = tokio::spawn(async move {
            let beacon_bridge =
                BeaconBridge::new(consensus_api, bridge_mode, Arc::new(portal_clients));

            beacon_bridge
                .launch()
                .instrument(tracing::trace_span!("beacon"))
                .await;
        });

        bridge_tasks.push(bridge_handle);
    }

    // Launch History Network portal bridge
    if bridge_config.network.contains(&NetworkKind::History) {
        match bridge_config.mode {
            BridgeMode::FourFours(_) => {
                let master_acc = MasterAccumulator::default();
                let header_oracle = HeaderOracle::new(master_acc);
                let era1_bridge = Era1Bridge::new(
                    bridge_config.mode,
                    portal_clients.expect("Failed to create history JSON-RPC clients"),
                    header_oracle,
                    bridge_config.epoch_acc_path,
                    bridge_config.gossip_limit,
                )
                .await?;
                let bridge_handle = tokio::spawn(async move {
                    era1_bridge
                        .launch()
                        .instrument(tracing::trace_span!("history(era1)"))
                        .await;
                });
                bridge_tasks.push(bridge_handle);
            }
            _ => {
                let execution_api = ExecutionApi::new(
                    bridge_config.el_provider,
                    bridge_config.el_provider_fallback,
                )
                .await?;
                let bridge_handle = tokio::spawn(async move {
                    let master_acc = MasterAccumulator::default();
                    let header_oracle = HeaderOracle::new(master_acc);

                    let bridge = HistoryBridge::new(
                        bridge_config.mode,
                        execution_api,
                        portal_clients.expect("Failed to create history JSON-RPC clients"),
                        header_oracle,
                        bridge_config.epoch_acc_path,
                        bridge_config.gossip_limit,
                    );

                    bridge
                        .launch()
                        .instrument(tracing::trace_span!("history"))
                        .await;
                });

                bridge_tasks.push(bridge_handle);
            }
        }
    }

    futures::future::join_all(bridge_tasks).await;

    Ok(())
}
