use clap::Parser;
use tokio::{
    sync::mpsc,
    time::{sleep, Duration},
};
use tracing::Instrument;

use ethportal_api::{
    jsonrpsee::http_client::{HttpClient, HttpClientBuilder},
    types::network::Subnetwork,
};
use portal_bridge::{
    api::{consensus::ConsensusApi, execution::ExecutionApi},
    bridge::{beacon::BeaconBridge, era1::Era1Bridge, history::HistoryBridge, state::StateBridge},
    census::Census,
    cli::BridgeConfig,
    handle::build_trin,
    types::mode::BridgeMode,
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
    let handle = build_trin(&bridge_config).map_err(|e| e.to_string())?;

    let web3_http_address = format!("http://127.0.0.1:{}", bridge_config.base_rpc_port);
    sleep(Duration::from_secs(5)).await;

    let portal_client: HttpClient = HttpClientBuilder::default()
        // increase default timeout to allow for trace_gossip requests that can take a long
        // time
        .request_timeout(Duration::from_secs(120))
        .build(web3_http_address.clone())
        .map_err(|e| e.to_string())?;

    let mut bridge_tasks = Vec::new();
    let mut census_handle = None;

    // Launch State Network portal bridge
    if bridge_config
        .portal_subnetworks
        .contains(&Subnetwork::State)
    {
        // Initialize the census
        let (census_tx, census_rx) = mpsc::unbounded_channel();
        let mut census = Census::new(portal_client.clone(), census_rx, &bridge_config);
        // initialize the census to acquire critical threshold view of network before gossiping
        census.init().await?;
        census_handle = Some(tokio::spawn(async move {
            census
                .run()
                .instrument(tracing::trace_span!("census"))
                .await;
        }));

        let state_bridge = StateBridge::new(
            bridge_config.mode.clone(),
            portal_client.clone(),
            bridge_config.offer_limit,
            census_tx,
            bridge_config.bridge_id,
        )
        .await?;

        state_bridge
            .launch()
            .instrument(tracing::trace_span!("state"))
            .await;
    } else {
        // Launch Beacon Network portal bridge
        if bridge_config
            .portal_subnetworks
            .contains(&Subnetwork::Beacon)
        {
            let bridge_mode = bridge_config.mode.clone();
            let consensus_api = ConsensusApi::new(
                bridge_config.cl_provider,
                bridge_config.cl_provider_fallback,
                bridge_config.request_timeout,
            )
            .await?;
            let portal_client_clone = portal_client.clone();
            let bridge_handle = tokio::spawn(async move {
                let beacon_bridge =
                    BeaconBridge::new(consensus_api, bridge_mode, portal_client_clone);

                beacon_bridge
                    .launch()
                    .instrument(tracing::trace_span!("beacon"))
                    .await;
            });

            bridge_tasks.push(bridge_handle);
        }

        // Launch History Network portal bridge
        if bridge_config
            .portal_subnetworks
            .contains(&Subnetwork::History)
        {
            let execution_api = ExecutionApi::new(
                bridge_config.el_provider,
                bridge_config.el_provider_fallback,
                bridge_config.request_timeout,
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
    }

    futures::future::join_all(bridge_tasks).await;
    drop(handle);
    if let Some(census_handle) = census_handle {
        drop(census_handle);
    }
    Ok(())
}
