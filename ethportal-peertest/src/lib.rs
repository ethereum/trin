pub mod cli;
pub mod jsonrpc;

pub use cli::PeertestConfig;
pub use jsonrpc::get_enode;

use std::sync::Arc;
use std::{thread, time};

use futures::future;

use trin_core::cli::TrinConfig;
use trin_core::jsonrpc::service::JsonRpcExiter;
use trin_core::portalnet::types::messages::SszEnr;

pub struct PeertestNode {
    pub enr: SszEnr,
    pub exiter: Arc<JsonRpcExiter>,
}

pub async fn launch_node(id: u16, bootnode_enr: Option<&String>) -> anyhow::Result<PeertestNode> {
    let discovery_port: u16 = 9000 + id;
    let discovery_port: String = discovery_port.to_string();
    let web3_ipc_path = format!("/tmp/ethportal-peertest-buddy-{id}.ipc");
    let trin_config_args: Vec<&str> = match bootnode_enr {
        Some(enr) => vec![
            "trin",
            "--internal-ip",
            "--bootnodes",
            enr.as_str(),
            "--discovery-port",
            discovery_port.as_str(),
            "--web3-ipc-path",
            web3_ipc_path.as_str(),
        ],
        None => vec![
            "trin",
            "--internal-ip",
            "--discovery-port",
            discovery_port.as_str(),
            "--web3-ipc-path",
            web3_ipc_path.as_str(),
        ],
    };
    let trin_config = TrinConfig::new_from(trin_config_args.iter()).unwrap();
    let web3_ipc_path = trin_config.web3_ipc_path.clone();
    let exiter = trin::run_trin(trin_config, String::new()).await.unwrap();
    let enr = get_enode(&web3_ipc_path)?;

    // Short sleep to make sure all peertest nodes can connect
    thread::sleep(time::Duration::from_secs(2));
    Ok(PeertestNode { enr, exiter })
}

pub async fn launch_peertest_nodes(count: u16) -> (PeertestNode, Vec<PeertestNode>) {
    // Bootnode uses a peertest id of 1
    let bootnode = launch_node(1, None).await.unwrap();
    let bootnode_enr = bootnode.enr.to_base64();
    // All other peertest node ids begin at 2, and increment from there
    let nodes = future::try_join_all(
        (2..count + 1)
            .into_iter()
            .map(|id| launch_node(id, Some(&bootnode_enr))),
    )
    .await
    .unwrap();
    (bootnode, nodes)
}
