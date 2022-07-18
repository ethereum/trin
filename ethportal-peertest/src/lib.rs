pub mod cli;
pub mod jsonrpc;
pub mod scenarios;

pub use cli::PeertestConfig;
pub use jsonrpc::get_enode;

use std::net::{IpAddr, Ipv4Addr};
use std::{sync::Arc, thread, time};

use futures::future;

use trin_core::{
    cli::TrinConfig, jsonrpc::service::JsonRpcExiter, portalnet::types::messages::SszEnr,
};

pub struct PeertestNode {
    pub enr: SszEnr,
    pub web3_ipc_path: String,
    pub exiter: Arc<JsonRpcExiter>,
}

pub struct Peertest {
    pub bootnode: PeertestNode,
    pub nodes: Vec<PeertestNode>,
}

impl Peertest {
    pub fn exit_all_nodes(&self) {
        self.bootnode.exiter.exit();
        self.nodes.iter().for_each(|node| node.exiter.exit());
    }
}

pub async fn launch_node(id: u16, bootnode_enr: Option<&SszEnr>) -> anyhow::Result<PeertestNode> {
    let discovery_port: u16 = 9000 + id;
    let discovery_port: String = discovery_port.to_string();
    let web3_ipc_path = format!("/tmp/ethportal-peertest-buddy-{id}.ipc");
    // This specific private key scheme is chosen to enforce that the first peer node will be in
    // the 256 kbucket of the bootnode, to ensure consistent `FindNodes` tests.
    let mut private_key = vec![id as u8; 3];
    private_key.append(&mut vec![0u8; 29]);
    let private_key = hex::encode(private_key);
    let trin_config = match bootnode_enr {
        Some(enr) => {
            let external_addr = format!(
                "{}:{}",
                enr.ip4().expect("bootnode must have IP"),
                discovery_port
            );
            let enr_base64 = enr.to_base64();
            let trin_config_args = vec![
                "trin",
                "--networks",
                "history,state",
                "--external-address",
                external_addr.as_str(),
                "--bootnodes",
                enr_base64.as_str(),
                "--discovery-port",
                discovery_port.as_str(),
                "--web3-ipc-path",
                web3_ipc_path.as_str(),
                "--unsafe-private-key",
                private_key.as_str(),
                "--ephemeral",
            ];
            TrinConfig::new_from(trin_config_args.iter()).unwrap()
        }
        None => {
            let ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
            let external_addr = format!("{}:{}", ip_addr, discovery_port);
            let trin_config_args = vec![
                "trin",
                "--networks",
                "history,state",
                "--external-address",
                external_addr.as_str(),
                "--discovery-port",
                discovery_port.as_str(),
                "--web3-ipc-path",
                web3_ipc_path.as_str(),
                "--unsafe-private-key",
                private_key.as_str(),
                "--ephemeral",
            ];
            TrinConfig::new_from(trin_config_args.iter()).unwrap()
        }
    };
    let web3_ipc_path = trin_config.web3_ipc_path.clone();
    let exiter = trin::run_trin(trin_config, String::new()).await.unwrap();
    let enr = get_enode(&web3_ipc_path)?;

    // Short sleep to make sure all peertest nodes can connect
    thread::sleep(time::Duration::from_secs(2));
    Ok(PeertestNode {
        enr,
        web3_ipc_path,
        exiter,
    })
}

pub async fn launch_peertest_nodes(count: u16) -> Peertest {
    // Bootnode uses a peertest id of 1
    let bootnode = launch_node(1, None).await.unwrap();
    let bootnode_enr = &bootnode.enr;
    // All other peertest node ids begin at 2, and increment from there
    let nodes = future::try_join_all(
        (2..count + 1)
            .into_iter()
            .map(|id| launch_node(id, Some(bootnode_enr))),
    )
    .await
    .unwrap();
    Peertest { bootnode, nodes }
}
