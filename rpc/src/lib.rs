#![warn(clippy::unwrap_used)]
#![warn(clippy::uninlined_format_args)]

mod beacon_rpc;
mod builder;
mod cors;
mod discv5_rpc;
mod errors;
mod eth_rpc;
mod fetch;
mod history_rpc;
mod rpc_server;
mod serde;
mod state_rpc;
mod web3_rpc;

use crate::jsonrpsee::server::ServerBuilder;
pub use crate::rpc_server::RpcServerHandle;
use beacon_rpc::BeaconNetworkApi;
pub use builder::{PortalRpcModule, RpcModuleBuilder, TransportRpcModuleConfig};
use discv5_rpc::Discv5Api;
use errors::RpcError;
use eth_rpc::EthApi;
use ethportal_api::{
    jsonrpsee,
    types::{
        cli::{TrinConfig, Web3TransportType, BEACON_NETWORK, HISTORY_NETWORK, STATE_NETWORK},
        jsonrpc::request::{BeaconJsonRpcRequest, HistoryJsonRpcRequest, StateJsonRpcRequest},
    },
};
use history_rpc::HistoryNetworkApi;
use state_rpc::StateNetworkApi;
use web3_rpc::Web3Api;

use crate::rpc_server::RpcServerConfig;
use portalnet::discovery::Discovery;
use reth_ipc::server::Builder as IpcServerBuilder;
use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
};
use tokio::sync::mpsc;

pub async fn launch_jsonrpc_server(
    trin_config: TrinConfig,
    discv5: Arc<Discovery>,
    history_handler: Option<mpsc::UnboundedSender<HistoryJsonRpcRequest>>,
    state_handler: Option<mpsc::UnboundedSender<StateJsonRpcRequest>>,
    beacon_handler: Option<mpsc::UnboundedSender<BeaconJsonRpcRequest>>,
) -> Result<RpcServerHandle, RpcError> {
    // Discv5 and Web3 modules are enabled with every network
    let mut modules = vec![PortalRpcModule::Discv5, PortalRpcModule::Web3];

    for network in trin_config.portal_subnetworks.iter() {
        match network.as_str() {
            HISTORY_NETWORK => {
                modules.push(PortalRpcModule::History);
                modules.push(PortalRpcModule::Eth);
            }
            STATE_NETWORK => modules.push(PortalRpcModule::State),
            BEACON_NETWORK => modules.push(PortalRpcModule::Beacon),
            _ => panic!("Unexpected network type: {network}"),
        }
    }

    let handle: RpcServerHandle = match trin_config.web3_transport {
        Web3TransportType::IPC => {
            let transport = TransportRpcModuleConfig::default().with_ipc(modules);
            let transport_modules = RpcModuleBuilder::new(discv5)
                .maybe_with_history(history_handler)
                .maybe_with_beacon(beacon_handler)
                .maybe_with_state(state_handler)
                .build(transport);

            RpcServerConfig::default()
                .with_ipc_endpoint(
                    trin_config
                        .web3_ipc_path
                        .to_str()
                        .expect("Path should be string"),
                )
                .with_ipc(IpcServerBuilder::default())
                .start(transport_modules)
                .await?
        }
        Web3TransportType::HTTP => {
            let transport = match trin_config.ws {
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
                    trin_config
                        .web3_http_address
                        .socket_addrs(|| None)
                        .expect("Invalid socket address")[0],
                )
                .with_http(ServerBuilder::default());
            let rpc_server_config = match trin_config.ws {
                true => rpc_server_config
                    .with_ws_address(SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::UNSPECIFIED,
                        trin_config.ws_port,
                    )))
                    .with_ws(ServerBuilder::default()),
                false => rpc_server_config,
            };
            rpc_server_config.start(transport_modules).await?
        }
    };

    Ok(handle)
}
