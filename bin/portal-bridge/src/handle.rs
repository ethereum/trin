use ethportal_api::{types::network::Subnetwork, utils::bytes::hex_encode};
use tokio::process::{Child, Command};

use crate::cli::BridgeConfig;

pub fn build_trin(bridge_config: &BridgeConfig) -> anyhow::Result<Child> {
    if !bridge_config.executable_path.is_file() {
        return Err(anyhow::anyhow!(
            "Trin executable path is not a file: {:?}",
            bridge_config.executable_path
        ));
    }
    let rpc_port = bridge_config.base_rpc_port;
    let udp_port = bridge_config.base_discovery_port;
    let private_key = hex_encode(bridge_config.private_key);
    let mut command = Command::new(bridge_config.executable_path.clone());

    command
        .kill_on_drop(true)
        .args(["--ephemeral"])
        .args(["--no-upnp"])
        .args(["--mb", "0"])
        .args(["--web3-transport", "http"])
        .args(["--network", &bridge_config.network.network().to_string()])
        .args(["--portal-subnetworks", &subnetworks_flag(bridge_config)])
        .args(["--unsafe-private-key", &private_key])
        .args(["--web3-http-address", &format!("http://0.0.0.0:{rpc_port}")])
        .args(["--discovery-port", &format!("{udp_port}")])
        .args(["--bootnodes", &bridge_config.bootnodes])
        .args([
            "--utp-transfer-limit",
            &bridge_config.offer_limit.to_string(),
        ]);
    if let Some(ip) = bridge_config.external_ip.clone() {
        command.args(["--external-address", &format!("{ip}:{udp_port}")]);
    }
    if let Some(client_metrics_url) = bridge_config.client_metrics_url {
        let url: String = client_metrics_url.to_string();
        command.args(["--enable-metrics-with-url", &url]);
    }

    Ok(command.spawn()?)
}

/// Returns the subnetwork flag to be passed to the trin handle.
///
/// This is a union of required subnetworks for each subnetwork from the config.
pub fn subnetworks_flag(bridge_config: &BridgeConfig) -> String {
    let subnetworks = match bridge_config.portal_subnetwork {
        Subnetwork::Beacon => vec![Subnetwork::Beacon],
        Subnetwork::History => vec![Subnetwork::History],
        // State requires both history and state
        Subnetwork::State => vec![Subnetwork::History, Subnetwork::State],
        subnetwork => panic!("Unsupported subnetwork: {subnetwork:?}"),
    }
    .into_iter()
    .map(|subnetwork| subnetwork.to_cli_arg());
    Vec::from_iter(subnetworks).join(",")
}
