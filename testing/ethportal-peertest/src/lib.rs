#![warn(clippy::uninlined_format_args)]
#![cfg(unix)]
pub mod scenarios;
pub mod utils;

use std::{net::Ipv4Addr, path::PathBuf, thread, time};

use ethportal_api::{
    types::{
        enr::Enr,
        network::{Network, Subnetwork},
    },
    utils::bytes::hex_encode,
    version::APP_NAME,
    Discv5ApiClient,
};
use futures::future;
use itertools::Itertools;
use jsonrpsee::async_client::Client;
use portalnet::constants::DEFAULT_DISCOVERY_PORT;
use rpc::RpcServerHandle;
use trin::{cli::TrinConfig, run::run_trin_from_trin_config};

pub struct PeertestNode {
    pub enr: Enr,
    pub ipc_client: Client,
    pub rpc_handle: RpcServerHandle,
}

pub struct Peertest {
    pub bootnode: PeertestNode,
    pub nodes: Vec<PeertestNode>,
}

impl Peertest {
    pub fn exit_all_nodes(&self) {
        self.bootnode.rpc_handle.clone().stop().unwrap();
        self.nodes
            .iter()
            .for_each(|node| node.rpc_handle.clone().stop().unwrap());
    }
}

async fn launch_node(trin_config: TrinConfig) -> anyhow::Result<PeertestNode> {
    let web3_ipc_path = trin_config.web3_ipc_path.clone();
    let trin_handle = run_trin_from_trin_config(trin_config).await.unwrap();

    // Short sleep to make sure all peertest nodes can connect
    thread::sleep(time::Duration::from_secs(2));
    let ipc_client = reth_ipc::client::IpcClientBuilder::default()
        .build(&web3_ipc_path.to_string_lossy())
        .await
        .unwrap();

    Ok(PeertestNode {
        enr: ipc_client.node_info().await.unwrap().enr,
        ipc_client,
        rpc_handle: trin_handle.rpc_server_handle,
    })
}

fn generate_trin_config(
    id: u16,
    network: Network,
    subnetworks: &[Subnetwork],
    bootnode_enr: Option<&Enr>,
) -> TrinConfig {
    let bootnodes_arg = bootnode_enr
        .map(|enr| enr.to_base64())
        .unwrap_or("none".to_string());

    let ip_addr = bootnode_enr
        .map(|enr| enr.ip4().expect("bootnode must have IP"))
        .unwrap_or(Ipv4Addr::new(127, 0, 0, 1));
    let discovery_port = (DEFAULT_DISCOVERY_PORT + id).to_string();
    let external_addr = format!("{ip_addr}:{discovery_port}");

    let web3_ipc_path = PathBuf::from(format!("/tmp/ethportal-peertest-buddy-{id}.ipc"));
    let web3_ipc_path_str = web3_ipc_path
        .to_str()
        .expect("web3_ipc_path should be unicode");

    // This specific private key scheme is chosen to enforce that the first peer node will be in
    // the 256 kbucket of the bootnode, to ensure consistent `FindNodes` tests.
    let mut private_key = vec![id as u8; 3];
    private_key.append(&mut vec![0u8; 29]);
    let private_key = hex_encode(private_key);
    let subnetworks = subnetworks
        .iter()
        .flat_map(Subnetwork::with_dependencies)
        .unique()
        .map(|subnetwork| subnetwork.to_cli_arg())
        .join(",");
    let network = network.to_string();

    let trin_config_args = [
        APP_NAME,
        "--network",
        &network,
        "--portal-subnetworks",
        &subnetworks,
        "--bootnodes",
        bootnodes_arg.as_str(),
        "--discovery-port",
        discovery_port.as_str(),
        "--external-address",
        external_addr.as_str(),
        "--web3-ipc-path",
        web3_ipc_path_str,
        "--unsafe-private-key",
        private_key.as_str(),
        "--ephemeral",
        "--max-radius",
        "100",
    ];
    TrinConfig::new_from(trin_config_args).unwrap()
}

pub async fn launch_peertest_nodes(
    count: u16,
    network: Network,
    subnetworks: &[Subnetwork],
) -> Peertest {
    // Bootnode uses a peertest id of 1
    let bootnode_config = generate_trin_config(1, network, subnetworks, None);
    let bootnode = launch_node(bootnode_config).await.unwrap();
    let bootnode_enr = &bootnode.enr;
    // All other peertest node ids begin at 2, and increment from there
    let nodes = future::try_join_all((2..=count).map(|id| {
        let node_config = generate_trin_config(id, network, subnetworks, Some(bootnode_enr));
        launch_node(node_config)
    }))
    .await
    .unwrap();
    Peertest { bootnode, nodes }
}
