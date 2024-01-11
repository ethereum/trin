use std::net::SocketAddr;

use tokio::process::{Child, Command};

use crate::cli::BridgeConfig;
use portalnet::socket::stun_for_external;

pub fn fluffy_handle(
    private_key: String,
    rpc_port: u16,
    udp_port: u16,
    bridge_config: BridgeConfig,
) -> anyhow::Result<Child> {
    let mut command = Command::new(bridge_config.executable_path);
    let listen_all_ips = SocketAddr::new("0.0.0.0".parse().expect("to parse ip"), udp_port);
    let ip = stun_for_external(&listen_all_ips).expect("to stun for external ip");
    command
        .kill_on_drop(true)
        .arg("--storage-capacity:0")
        .arg("--rpc")
        .arg(format!("--rpc-port:{rpc_port}"))
        .arg(format!("--udp-port:{udp_port}"))
        .arg(format!("--nat:extip:{}", ip.ip()))
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
    if let Some(ip) = bridge_config.external_ip {
        command.arg(format!("--nat:extip:{ip}"));
    }
    Ok(command.spawn()?)
}

pub fn trin_handle(
    private_key: String,
    rpc_port: u16,
    udp_port: u16,
    bridge_config: BridgeConfig,
) -> anyhow::Result<Child> {
    let mut command = Command::new(bridge_config.executable_path);
    let networks = bridge_config
        .network
        .into_iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(",");

    command
        .kill_on_drop(true)
        .args(["--ephemeral"])
        .args(["--mb", "0"])
        .args(["--web3-transport", "http"])
        .args(["--portal-subnetworks", &networks])
        .args(["--unsafe-private-key", &private_key])
        .args([
            "--web3-http-address",
            &format!("http://127.0.0.1:{rpc_port}"),
        ])
        .args(["--discovery-port", &format!("{udp_port}")])
        .args(["--bootnodes", &bridge_config.bootnodes]);
    if let Some(ip) = bridge_config.external_ip {
        command.args(["--external-address", &format!("{ip}:{udp_port}")]);
    }
    if let Some(client_metrics_url) = bridge_config.client_metrics_url {
        let url: String = client_metrics_url.to_string();
        command.args(["--enable-metrics-with-url", &url]);
    }
    Ok(command.spawn()?)
}
