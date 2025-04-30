#![warn(clippy::unwrap_used)]
#![warn(clippy::uninlined_format_args)]

mod beacon_rpc;
mod builder;
pub mod config;
mod cors;
mod discv5_rpc;
mod errors;
mod eth_rpc;
mod evm_state;
mod fetch;
mod history_rpc;
mod ping_extension;
mod rpc_server;
mod serde;
mod state_rpc;
mod web3_rpc;

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
};

use beacon_rpc::BeaconNetworkApi;
pub use builder::{PortalRpcModule, RpcModuleBuilder, TransportRpcModuleConfig};
use config::RpcConfig;
use discv5_rpc::Discv5Api;
use errors::RpcError;
use eth_rpc::EthApi;
use ethportal_api::{
    jsonrpsee,
    types::{
        jsonrpc::request::{BeaconJsonRpcRequest, HistoryJsonRpcRequest, StateJsonRpcRequest},
        network::Subnetwork,
    },
};
use history_rpc::HistoryNetworkApi;
use portalnet::discovery::Discovery;
use reth_ipc::server::Builder as IpcServerBuilder;
use state_rpc::StateNetworkApi;
use tokio::sync::mpsc;
use trin_utils::cli::Web3TransportType;
use web3_rpc::Web3Api;

pub use crate::rpc_server::RpcServerHandle;
use crate::{jsonrpsee::server::ServerBuilder, rpc_server::RpcServerConfig};

pub async fn launch_jsonrpc_server(
    rpc_config: RpcConfig,
    portal_subnetworks: Arc<Vec<Subnetwork>>,
    discv5: Arc<Discovery>,
    history_handler: Option<mpsc::UnboundedSender<HistoryJsonRpcRequest>>,
    state_handler: Option<mpsc::UnboundedSender<StateJsonRpcRequest>>,
    beacon_handler: Option<mpsc::UnboundedSender<BeaconJsonRpcRequest>>,
) -> Result<RpcServerHandle, RpcError> {
    // Discv5 and Web3 modules are enabled with every network
    let mut modules = vec![PortalRpcModule::Discv5, PortalRpcModule::Web3];

    for network in portal_subnetworks.iter() {
        match network {
            Subnetwork::History => {
                modules.push(PortalRpcModule::History);
                modules.push(PortalRpcModule::Eth);
            }
            Subnetwork::State => modules.push(PortalRpcModule::State),
            Subnetwork::Beacon => modules.push(PortalRpcModule::Beacon),
            _ => return Err(RpcError::Custom("Unsupported subnetwork".to_string())),
        }
    }

    let handle: RpcServerHandle = match rpc_config.web3_transport {
        Web3TransportType::IPC => {
            let transport = TransportRpcModuleConfig::default().with_ipc(modules);
            let transport_modules = RpcModuleBuilder::new(discv5)
                .maybe_with_history(history_handler)
                .maybe_with_beacon(beacon_handler)
                .maybe_with_state(state_handler)
                .build(transport);

            RpcServerConfig::default()
                .with_ipc_endpoint(
                    rpc_config
                        .web3_ipc_path
                        .to_str()
                        .expect("Path should be string"),
                )
                .with_ipc(IpcServerBuilder::default())
                .start(transport_modules)
                .await?
        }
        Web3TransportType::HTTP => {
            let transport = match rpc_config.ws {
                true => TransportRpcModuleConfig::default().with_ws(modules.clone()),
                false => TransportRpcModuleConfig::default(),
            };
            let transport = transport.with_http(modules);

            let transport_modules = RpcModuleBuilder::new(discv5)
                .maybe_with_history(history_handler)
                .maybe_with_beacon(beacon_handler)
                .maybe_with_state(state_handler)
                .build(transport);

            let rpc_server_config = RpcServerConfig::default()
                .with_http_address(
                    rpc_config
                        .web3_http_address
                        .socket_addrs(|| None)
                        .expect("Invalid socket address")[0],
                )
                .with_http(ServerBuilder::default());
            let rpc_server_config = match rpc_config.ws {
                true => rpc_server_config
                    .with_ws_address(SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::UNSPECIFIED,
                        rpc_config.ws_port,
                    )))
                    .with_ws(ServerBuilder::default()),
                false => rpc_server_config,
            };
            rpc_server_config.start(transport_modules).await?
        }
    };

    Ok(handle)
}
