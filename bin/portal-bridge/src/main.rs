use clap::Parser;
use ethportal_api::{
    jsonrpsee::http_client::{HttpClient, HttpClientBuilder},
    types::network::Subnetwork,
};
use portal_bridge::{
    api::consensus::ConsensusApi,
    bridge::{beacon::BeaconBridge, e2hs::E2HSBridge, state::StateBridge},
    census::Census,
    cli::BridgeConfig,
    handle::build_trin,
    types::mode::BridgeMode,
};
use tokio::time::{sleep, Duration};
use tracing::Instrument;
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
    let handle = build_trin(&bridge_config).map_err(|e| e.to_string())?;

    let web3_http_address = format!("http://127.0.0.1:{}", bridge_config.base_rpc_port);
    sleep(Duration::from_secs(10)).await;

    let portal_client: HttpClient = HttpClientBuilder::default()
        // increase default timeout to allow for trace_gossip requests that can take a long
        // time
        .request_timeout(Duration::from_secs(120))
        .build(web3_http_address.clone())
        .map_err(|e| e.to_string())?;

    let census_handle = match bridge_config.portal_subnetwork {
        Subnetwork::Beacon => {
            // Create and initialize the census to acquire critical view of network before gossiping
            let mut census = Census::new(portal_client.clone(), &bridge_config);
            let census_handle = census.init([Subnetwork::Beacon]).await?;

            let bridge_mode = bridge_config.mode.clone();
            let consensus_api = ConsensusApi::new(
                bridge_config.cl_provider.clone(),
                bridge_config.cl_provider_fallback.clone(),
                bridge_config.request_timeout,
            )
            .await?;
            let portal_client_clone = portal_client.clone();
            let beacon_bridge =
                BeaconBridge::new(consensus_api, bridge_mode, portal_client_clone, census);

            beacon_bridge
                .launch()
                .instrument(tracing::trace_span!("beacon"))
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
                    let mut census = Census::new(portal_client.clone(), &bridge_config);
                    let census_handle = census.init([Subnetwork::History]).await?;

                    let e2hs_bridge = E2HSBridge::new(
                        portal_client,
                        bridge_config.offer_limit,
                        e2hs_range,
                        bridge_config.e2hs_randomize,
                        census,
                    )
                    .await?;
                    e2hs_bridge
                        .launch()
                        .instrument(tracing::trace_span!("history(e2hs)"))
                        .await;
                    census_handle
                }
                _ => panic!("Unsupported bridge mode for History network"),
            }
        }
        Subnetwork::State => {
            // Create and initialize the census to acquire critical view of network before gossiping
            let mut census = Census::new(portal_client.clone(), &bridge_config);
            let census_handle = census.init([Subnetwork::State]).await?;

            let state_bridge = StateBridge::new(
                bridge_config.mode.clone(),
                portal_client.clone(),
                bridge_config.offer_limit,
                census,
                bridge_config.bridge_id,
                bridge_config.data_dir,
            )
            .await?;

            state_bridge
                .launch()
                .instrument(tracing::trace_span!("state"))
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

    drop(handle);
    census_handle.abort();
    drop(census_handle);
    Ok(())
}
