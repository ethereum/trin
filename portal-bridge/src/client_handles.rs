use std::{collections::HashSet, net::SocketAddr};

use tokio::process::{Child, Command};

use crate::{cli::BridgeConfig, types::network::NetworkKind};
use ethportal_api::utils::bytes::hex_encode;
use portalnet::socket::stun_for_external;

pub fn fluffy_handle(bridge_config: &BridgeConfig) -> anyhow::Result<Child> {
    let rpc_port = bridge_config.base_rpc_port;
    let udp_port = bridge_config.base_discovery_port;
    let private_key = hex_encode(bridge_config.private_key);
    let mut command = Command::new(bridge_config.executable_path.clone());
    let listen_all_ips = SocketAddr::new("0.0.0.0".parse().expect("to parse ip"), udp_port);
    let ip = stun_for_external(&listen_all_ips).expect("to stun for external ip");

    command
        .kill_on_drop(true)
        .arg("--storage-capacity:0")
        .arg("--rpc")
        .arg(format!("--rpc-port:{rpc_port}"))
        .arg(format!("--udp-port:{udp_port}"))
        .arg(format!("--nat:extip:{}", ip.ip()))
        .arg(format!(
            "--network:{}",
            bridge_config.network.get_network_name()
        ))
        .arg(format!(
            "--portal-subnetworks:{}",
            subnetworks_flag(bridge_config)
        ))
        .arg(format!("--netkey-unsafe:{private_key}"));
    if let Some(client_metrics_url) = bridge_config.client_metrics_url {
        let address = client_metrics_url.ip().to_string();
        let port = client_metrics_url.port();
        command
            .arg("--metrics")
            .arg(format!("--metrics-address:{address}"))
            .arg(format!("--metrics-port:{port}"));
    }
    if bridge_config.bootnodes != "default" {
        for enr in bridge_config.bootnodes.split(',') {
            command.args(["--bootstrap-node", enr]);
        }
    }
    if let Some(ip) = bridge_config.external_ip.clone() {
        command.arg(format!("--nat:extip:{ip}"));
    }
    Ok(command.spawn()?)
}

pub fn trin_handle(bridge_config: &BridgeConfig) -> anyhow::Result<Child> {
    let rpc_port = bridge_config.base_rpc_port;
    let udp_port = bridge_config.base_discovery_port;
    let private_key = hex_encode(bridge_config.private_key);
    let mut command = Command::new(bridge_config.executable_path.clone());

    command
        .kill_on_drop(true)
        .args(["--ephemeral"])
        .args(["--mb", "0"])
        .args(["--web3-transport", "http"])
        .args(["--network", bridge_config.network.get_network_name()])
        .args(["--portal-subnetworks", &subnetworks_flag(bridge_config)])
        .args(["--unsafe-private-key", &private_key])
        .args([
            "--web3-http-address",
            &format!("http://127.0.0.1:{rpc_port}"),
        ])
        .args(["--discovery-port", &format!("{udp_port}")])
        .args(["--bootnodes", &bridge_config.bootnodes]);
    if let Some(ip) = bridge_config.external_ip.clone() {
        command.args(["--external-address", &format!("{ip}:{udp_port}")]);
    }
    if let Some(client_metrics_url) = bridge_config.client_metrics_url {
        let url: String = client_metrics_url.to_string();
        command.args(["--enable-metrics-with-url", &url]);
    }
    Ok(command.spawn()?)
}

/// Returns the subnetwork flag to be passed to the trin/fluffy handle.
///
/// This is a union of required subnetworks for each subnetwork from the config.
pub fn subnetworks_flag(bridge_config: &BridgeConfig) -> String {
    let subnetworks = bridge_config
        .portal_subnetworks
        .iter()
        .flat_map(|subnetwork| match subnetwork {
            NetworkKind::Beacon => vec![NetworkKind::Beacon],
            NetworkKind::History => vec![NetworkKind::History],
            NetworkKind::State => vec![NetworkKind::History, NetworkKind::State],
        })
        .map(|network_kind| network_kind.to_string())
        .collect::<HashSet<_>>();
    Vec::from_iter(subnetworks).join(",")
}
