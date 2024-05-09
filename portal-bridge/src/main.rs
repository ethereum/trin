use clap::Parser;
use tokio::time::{sleep, Duration};
use tracing::Instrument;

use ethportal_api::jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use portal_bridge::{
    api::{consensus::ConsensusApi, execution::ExecutionApi},
    bridge::{beacon::BeaconBridge, era1::Era1Bridge, history::HistoryBridge, state::StateBridge},
    cli::BridgeConfig,
    types::{mode::BridgeMode, network::NetworkKind},
};
use trin_utils::log::init_tracing_logger;
use trin_validation::oracle::HeaderOracle;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing_logger();

    let bridge_config = BridgeConfig::parse();

    if let Some(addr) = bridge_config.metrics_url {
        prometheus_exporter::start(addr)?;
    }

    // start the bridge client, need to keep the handle alive
    // for bridge to work inside docker containers
    let handle = bridge_config
        .client_type
        .build_handle(&bridge_config)
        .map_err(|e| e.to_string())?;

    let web3_http_address = format!("http://127.0.0.1:{}", bridge_config.base_rpc_port);
    sleep(Duration::from_secs(5)).await;

    let portal_client: HttpClient = HttpClientBuilder::default()
        // increase default timeout to allow for trace_gossip requests that can take a long
        // time
        .request_timeout(Duration::from_secs(120))
        .build(web3_http_address.clone())
        .map_err(|e| e.to_string())?;

    let mut bridge_tasks = Vec::new();

    // Launch Beacon Network portal bridge
    if bridge_config
        .portal_subnetworks
        .contains(&NetworkKind::Beacon)
    {
        let bridge_mode = bridge_config.mode.clone();
        let consensus_api = ConsensusApi::new(
            bridge_config.cl_provider,
            bridge_config.cl_provider_fallback,
        )
        .await?;
        let portal_client_clone = portal_client.clone();
        let bridge_handle = tokio::spawn(async move {
            let beacon_bridge = BeaconBridge::new(consensus_api, bridge_mode, portal_client_clone);

            beacon_bridge
                .launch()
                .instrument(tracing::trace_span!("beacon"))
                .await;
        });

        bridge_tasks.push(bridge_handle);
    }

    // Launch State Network portal bridge
    if bridge_config
        .portal_subnetworks
        .contains(&NetworkKind::State)
    {
        let bridge_mode = bridge_config.mode.clone();
        let portal_client_clone = portal_client.clone();
        let epoch_acc_path = bridge_config.epoch_acc_path.clone();
        let header_oracle = HeaderOracle::default();
        let state_bridge = StateBridge::new(
            bridge_mode,
            portal_client_clone,
            header_oracle,
            epoch_acc_path,
            bridge_config.gossip_limit,
        )
        .await?;
        let bridge_handle = tokio::spawn(async move {
            state_bridge
                .launch()
                .instrument(tracing::trace_span!("state"))
                .await;
        });
        bridge_tasks.push(bridge_handle);
    }

    // Launch History Network portal bridge
    if bridge_config
        .portal_subnetworks
        .contains(&NetworkKind::History)
    {
        let execution_api = ExecutionApi::new(
            bridge_config.el_provider,
            bridge_config.el_provider_fallback,
        )
        .await?;
        match bridge_config.mode {
            BridgeMode::FourFours(_) => {
                let header_oracle = HeaderOracle::default();
                let era1_bridge = Era1Bridge::new(
                    bridge_config.mode,
                    portal_client,
                    header_oracle,
                    bridge_config.epoch_acc_path,
                    bridge_config.gossip_limit,
                    execution_api,
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
                let bridge_handle = tokio::spawn(async move {
                    let header_oracle = HeaderOracle::default();

                    let bridge = HistoryBridge::new(
                        bridge_config.mode,
                        execution_api,
                        portal_client,
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
    drop(handle);
    Ok(())
}
