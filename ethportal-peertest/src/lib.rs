#![warn(clippy::uninlined_format_args)]
#![cfg(unix)]
pub mod scenarios;
pub mod utils;

use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    thread, time,
};

use ethportal_api::{
    types::{
        cli::{TrinConfig, DEFAULT_DISCOVERY_PORT},
        enr::Enr,
    },
    utils::bytes::hex_encode,
    Discv5ApiClient,
};
use futures::future;
use jsonrpsee::async_client::Client;
use rpc::RpcServerHandle;

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
    let rpc_handle = trin::run_trin(trin_config).await.unwrap();

    // Short sleep to make sure all peertest nodes can connect
    thread::sleep(time::Duration::from_secs(2));
    let ipc_client = reth_ipc::client::IpcClientBuilder::default()
        .build(web3_ipc_path)
        .await
        .unwrap();

    Ok(PeertestNode {
        enr: ipc_client.node_info().await.unwrap().enr,
        ipc_client,
        rpc_handle,
    })
}

fn generate_trin_config(id: u16, bootnode_enr: Option<&Enr>) -> TrinConfig {
    let discovery_port: u16 = DEFAULT_DISCOVERY_PORT + id;
    let discovery_port: String = discovery_port.to_string();
    let web3_ipc_path = PathBuf::from(format!("/tmp/ethportal-peertest-buddy-{id}.ipc"));
    // This specific private key scheme is chosen to enforce that the first peer node will be in
    // the 256 kbucket of the bootnode, to ensure consistent `FindNodes` tests.
    let mut private_key = vec![id as u8; 3];
    private_key.append(&mut vec![0u8; 29]);
    let private_key = hex_encode(private_key);
    match bootnode_enr {
        Some(enr) => {
            let external_addr = format!(
                "{}:{}",
                enr.ip4().expect("bootnode must have IP"),
                discovery_port
            );
            let enr_base64 = enr.to_base64();
            let web3_ipc_path_str = web3_ipc_path.as_path().display().to_string();
            let trin_config_args = vec![
                "trin",
                "--portal-subnetworks",
                "history,beacon,state",
                "--external-address",
                external_addr.as_str(),
                "--bootnodes",
                enr_base64.as_str(),
                "--discovery-port",
                discovery_port.as_str(),
                "--web3-ipc-path",
                &web3_ipc_path_str[..],
                "--unsafe-private-key",
                private_key.as_str(),
                "--ephemeral",
            ];
            TrinConfig::new_from(trin_config_args.iter()).unwrap()
        }
        None => {
            let ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
            let external_addr = format!("{ip_addr}:{discovery_port}");
            let web3_ipc_path_str = web3_ipc_path.as_path().display().to_string();
            let trin_config_args = vec![
                "trin",
                "--portal-subnetworks",
                "history,beacon,state",
                "--external-address",
                external_addr.as_str(),
                "--bootnodes",
                "none",
                "--discovery-port",
                discovery_port.as_str(),
                "--web3-ipc-path",
                &web3_ipc_path_str[..],
                "--unsafe-private-key",
                private_key.as_str(),
                "--ephemeral",
            ];
            TrinConfig::new_from(trin_config_args.iter()).unwrap()
        }
    }
}

pub async fn launch_peertest_nodes(count: u16) -> Peertest {
    // Bootnode uses a peertest id of 1
    let bootnode_config = generate_trin_config(1, None);
    let bootnode = launch_node(bootnode_config).await.unwrap();
    let bootnode_enr = &bootnode.enr;
    // All other peertest node ids begin at 2, and increment from there
    let nodes = future::try_join_all((2..count + 1).map(|id| {
        let node_config = generate_trin_config(id, Some(bootnode_enr));
        launch_node(node_config)
    }))
    .await
    .unwrap();
    Peertest { bootnode, nodes }
}
