pub mod cli;
pub mod jsonrpc;

pub use cli::PeertestConfig;
pub use jsonrpc::{get_enode, test_jsonrpc_endpoints_over_http, test_jsonrpc_endpoints_over_ipc};

use std::sync::Arc;

use trin_core::cli::TrinConfig;
use trin_core::jsonrpc::service::JsonRpcExiter;

pub async fn launch_buddy_node() -> (String, Arc<JsonRpcExiter>) {
    // Run a client, as a buddy peer for ping tests, etc.
    let trin_config = TrinConfig::new_from(
        [
            "trin",
            "--internal-ip",
            "--unsafe-private-key",
            "7261696e626f7773756e69636f726e737261696e626f7773756e69636f726e73",
            "--discovery-port",
            "9001",
            "--web3-ipc-path",
            "/tmp/ethportal-peertest-buddy.ipc",
        ]
        .iter(),
    )
    .unwrap();
    let web3_ipc_path = trin_config.web3_ipc_path.clone();
    let exiter = trin::run_trin(trin_config, String::new()).await.unwrap();
    let enode = get_enode(&web3_ipc_path).unwrap();
    (enode, exiter)
}
