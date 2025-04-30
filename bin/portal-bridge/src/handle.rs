use std::str::FromStr;

use anyhow::anyhow;
use ethportal_api::types::network::Subnetwork;
use portalnet::{
    bootnodes::Bootnodes,
    config::{PortalnetConfig, DISCV5_SESSION_CACHE_CAPACITY},
    utils::db::configure_node_data_dir,
};
use trin::{run_trin, SubnetworkOverlays};
use trin_utils::dir::setup_data_dir;

use crate::cli::BridgeConfig;

const APP_NAME: &str = "portal-bridge";

pub async fn start_trin(bridge_config: &BridgeConfig) -> anyhow::Result<SubnetworkOverlays> {
    // Setup temp trin data directory if we're in ephemeral mode
    let trin_data_dir = setup_data_dir(APP_NAME, None, true)?;

    // Configure node data dir based on the provided private key
    let (node_data_dir, private_key) = configure_node_data_dir(
        &trin_data_dir,
        Some(bridge_config.private_key),
        bridge_config.network.network(),
    )?;

    let portalnet_config = PortalnetConfig {
        external_addr: bridge_config.external_ip,
        private_key,
        listen_port: bridge_config.base_discovery_port,
        bootnodes: Bootnodes::from_str(&bridge_config.bootnodes)?
            .to_enrs(bridge_config.network.network()),
        no_stun: false,
        no_upnp: true,
        discv5_session_cache_capacity: DISCV5_SESSION_CACHE_CAPACITY,
        disable_poke: false,
        trusted_block_root: None,
        utp_transfer_limit: bridge_config.offer_limit,
    };
    let node_runtime_config = bridge_config.as_node_runtime_config(node_data_dir);

    run_trin(portalnet_config, node_runtime_config)
        .await
        .map_err(|err| anyhow!("Failed to run trin error: {err:?}"))
}

/// Returns the subnetwork flag to be passed to the trin handle.
///
/// This is a union of required subnetworks for each subnetwork from the config.
pub fn subnetworks_flag(bridge_config: &BridgeConfig) -> Vec<Subnetwork> {
    match bridge_config.portal_subnetwork {
        Subnetwork::Beacon => vec![Subnetwork::Beacon],
        // History requires beacon and history
        Subnetwork::History => vec![Subnetwork::Beacon, Subnetwork::History],
        // State requires beacon, history and state
        Subnetwork::State => vec![Subnetwork::Beacon, Subnetwork::History, Subnetwork::State],
        subnetwork => panic!("Unsupported subnetwork: {subnetwork:?}"),
    }
}
