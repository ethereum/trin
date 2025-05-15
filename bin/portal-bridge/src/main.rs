use std::future::Future;

use clap::Parser;
use ethereum_rpc_client::consensus::ConsensusApi;
use ethportal_api::types::network::Subnetwork;
use portal_bridge::{
    bridge::{beacon::BeaconBridge, e2hs::E2HSBridge, state::StateBridge},
    census::Census,
    cli::BridgeConfig,
    handle::start_trin,
    types::mode::BridgeMode,
};
use tracing::{info, warn, Instrument};
use trin_utils::log::init_tracing_logger;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing_logger();

    let bridge_config = BridgeConfig::parse();

    if let Some(addr) = bridge_config.metrics_url {
        prometheus_exporter::start(addr)?;
    }

    // start the bridge client, need to keep the handle alive
    // for bridge to work inside docker containers
    let subnetwork_overlays = start_trin(&bridge_config)
        .await
        .map_err(|err| err.to_string())?;

    let census_handle = match bridge_config.portal_subnetwork {
        Subnetwork::Beacon => {
            // Create and initialize the census to acquire critical view of network before gossiping
            let mut census = Census::new(subnetwork_overlays.clone(), &bridge_config);
            let census_handle = census.init([Subnetwork::Beacon]).await?;

            let bridge_mode = bridge_config.mode.clone();
            let consensus_api = ConsensusApi::new(
                bridge_config.cl_provider.clone(),
                bridge_config.cl_provider_fallback.clone(),
                bridge_config.request_timeout,
            )
            .await?;
            let beacon_network = subnetwork_overlays
                .beacon
                .expect("Beacon network not found in SubnetworkOverlays");
            let beacon_bridge =
                BeaconBridge::new(consensus_api, bridge_mode, beacon_network, census);

            run_with_shutdown(
                beacon_bridge
                    .launch()
                    .instrument(tracing::trace_span!("beacon")),
            )
            .await;

            census_handle
        }
        Subnetwork::History => {
            match bridge_config.mode {
                BridgeMode::E2HS => {
                    let Some(e2hs_range) = bridge_config.e2hs_range.clone() else {
                        panic!("e2hs_range must be set for E2HS mode");
                    };
                    // Create and initialize the census to acquire critical view of network before
                    // gossiping
                    let mut census = Census::new(subnetwork_overlays.clone(), &bridge_config);
                    let census_handle = census.init([Subnetwork::History]).await?;

                    let history_network = subnetwork_overlays
                        .history
                        .expect("History network not found in SubnetworkOverlays");
                    let e2hs_bridge = E2HSBridge::new(
                        history_network,
                        bridge_config.offer_limit,
                        e2hs_range,
                        bridge_config.e2hs_randomize,
                        census,
                    )
                    .await?;

                    run_with_shutdown(
                        e2hs_bridge
                            .launch()
                            .instrument(tracing::trace_span!("history(e2hs)")),
                    )
                    .await;

                    census_handle
                }
                _ => panic!("Unsupported bridge mode for History network"),
            }
        }
        Subnetwork::State => {
            // Create and initialize the census to acquire critical view of network before gossiping
            let mut census = Census::new(subnetwork_overlays.clone(), &bridge_config);
            let census_handle = census.init([Subnetwork::State]).await?;
            let state_network = subnetwork_overlays
                .state
                .expect("State network not found in SubnetworkOverlays");
            let state_bridge = StateBridge::new(
                bridge_config.mode.clone(),
                state_network,
                bridge_config.offer_limit,
                census,
                bridge_config.bridge_id,
                bridge_config.data_dir,
            )
            .await?;

            run_with_shutdown(
                state_bridge
                    .launch()
                    .instrument(tracing::trace_span!("state")),
            )
            .await;

            census_handle
        }
        _ => {
            panic!(
                "Unsupported portal subnetwork: {:?}",
                bridge_config.portal_subnetwork
            );
        }
    };

    census_handle.abort();
    drop(census_handle);
    Ok(())
}

/// Runs a bridge future with a shutdown handler.
///
/// Pass the bridge's `launch()` future into this.
pub async fn run_with_shutdown<F>(bridge_future: F)
where
    F: Future<Output = ()>,
{
    let shutdown_handle = tokio::spawn(async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for Ctrl+C");
        info!("Ctrl+C received. Initiating shutdown...");
    });

    tokio::select! {
        _ = bridge_future  => {
            info!("Finished all bridge tasks");
        }
        _ = shutdown_handle => {
            warn!("Shutdown signal received during bridge execution.");
        }
    }
}
