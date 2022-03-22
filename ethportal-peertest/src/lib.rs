pub mod cli;
pub mod jsonrpc;

pub use cli::PeertestConfig;
pub use jsonrpc::get_enode;

use std::sync::Arc;

use futures::future;

use trin_core::cli::TrinConfig;
use trin_core::jsonrpc::service::JsonRpcExiter;

pub struct PeertestNode {
    pub enr: String,
    pub exiter: Arc<JsonRpcExiter>,
}

pub struct AllPeertestNodes {
    pub bootnode: PeertestNode,
    pub nodes: Vec<PeertestNode>,
}

impl AllPeertestNodes {
    pub fn exit(&self) {
        self.bootnode.exiter.exit();
        self.nodes.iter().for_each(|node| node.exiter.exit());
    }
}

pub async fn launch_node(mut id: u8, bootnode: Option<&String>) -> anyhow::Result<PeertestNode> {
    // The bootnode's id is 1, the other node ids are subsequently incremented by one
    if bootnode.is_some() {
        id += 1;
    }
    // Run a client, as a buddy peer for ping tests, etc.
    let discovery_port = format!("900{id}");
    let web3_ipc_path = format!("/tmp/ethportal-peertest-buddy-{id}.ipc");
    let trin_config_args: Vec<&str> = match bootnode {
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
    let enr = get_enode(&web3_ipc_path).unwrap();
    Ok(PeertestNode { enr, exiter })
}

pub async fn launch_peertest_nodes(count: u8) -> AllPeertestNodes {
    let bootnode = launch_node(1, None).await.unwrap();
    let nodes = future::try_join_all(
        (1..count)
            .into_iter()
            .map(|id| launch_node(id, Some(&bootnode.enr))),
    )
    .await
    .unwrap();
    AllPeertestNodes { bootnode, nodes }
}
