use crate::cli::BridgeConfig;
use anyhow::bail;
use portalnet::socket::stun_for_external;
use std::net::SocketAddr;
use tokio::process::{Child, Command};

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
        .arg("--storage-size:0")
        .arg("--rpc")
        .arg(format!("--rpc-port:{rpc_port}"))
        .arg(format!("--udp-port:{udp_port}"))
        .arg(format!("--nat:extip:{}", ip.ip()))
        .arg("--network:testnet0")
        .arg("--table-ip-limit:1024")
        .arg("--bucket-ip-limit:24")
        .arg(format!("--netkey-unsafe:{private_key}"));
    if let Some(metrics_url) = bridge_config.metrics_url {
        let address = match metrics_url.host_str() {
            Some(address) => address,
            None => bail!("Invalid metrics url address"),
        };
        let port = match metrics_url.port() {
            Some(port) => port,
            None => bail!("Invalid metrics url port"),
        };
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
    if !bridge_config.external_ip.is_empty() {
        command.arg(format!("--nat:extip:{}", bridge_config.external_ip));
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
        .args(["--networks", &networks])
        .args(["--unsafe-private-key", &private_key])
        .args([
            "--web3-http-address",
            &format!("http://127.0.0.1:{rpc_port}"),
        ])
        .args(["--discovery-port", &format!("{udp_port}")])
        .args(["--bootnodes", &bridge_config.bootnodes]);
    if !bridge_config.external_ip.is_empty() {
        command.args([
            "--external-address",
            &format!("{}:{}", bridge_config.external_ip, udp_port),
        ]);
    }
    if let Some(metrics_url) = bridge_config.metrics_url {
        let url: String = metrics_url.into();
        command.args(["--enable-metrics-with-url", &url]);
    }
    Ok(command.spawn()?)
}
