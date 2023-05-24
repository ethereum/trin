pub mod constants;
pub mod scenarios;

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::{thread, time};

use ethportal_api::jsonrpsee::server::ServerHandle;
use ethportal_api::Discv5ApiClient;
use futures::future;
use httpmock::prelude::{MockServer, POST};
use jsonrpsee::async_client::Client;
use serde_json::json;

use ethportal_api::types::enr::Enr;
use ethportal_api::types::{cli::TrinConfig, provider::TrustedProvider};
use ethportal_api::utils::bytes::hex_encode;

pub fn setup_mock_trusted_http_server() -> MockServer {
    let server = MockServer::start();
    server.mock(|when, then| {
        // setup up a mock trusted http response for validating accepted content
        // inside test_offer_accept scenario
        when.method(POST)
            .body_contains("eth_getBlockByNumber");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "jsonrpc": "2.0",
                "id": 0,
                "result": {
                    "baseFeePerGas": "0x1aae1651b6",
                    "difficulty": "0x327bd7ad3116ce",
                    "extraData": "0x457468657265756d50504c4e532f326d696e6572735f55534133",
                    "gasLimit": "0x1c9c364",
                    "gasUsed": "0x140db1",
                    "hash": "0x720704f3aa11c53cf344ea069db95cecb81ad7453c8f276b2a1062979611f09c",
                    "logsBloom": "0x00200000400000001000400080080000000000010004010001000008000000002000110000000000000090020001110402008000080208040010000000a8000000000000000000210822000900205020000000000160020020000400800040000000000042080000000400004008084020001000001004004000001000000000000001000000110000040000010200844040048101000008002000404810082002800000108020000200408008000100000000000000002020000b0001008060090200020000005000040000000000000040000000202101000000a00002000003420000800400000020100002000000000000000c000400000010000001001",
                    "miner": "0x00192fb10df37c9fb26829eb2cc623cd1bf599e8",
                    "mixHash": "0xf1a32e24eb62f01ec3f2b3b5893f7be9062fbf5482bc0d490a54352240350e26",
                    "nonce": "0x2087fbb243327696",
                    "number": "0xe147ed",
                    "parentHash": "0x2c58e3212c085178dbb1277e2f3c24b3f451267a75a234945c1581af639f4a7a",
                    "receiptsRoot": "0x168a3827607627e781941dc777737fc4b6beb69a8b139240b881992b35b854ea",
                    "sha3Uncles": "0x58a694212e0416353a4d3865ccf475496b55af3a3d3b002057000741af973191",
                    "size": "0x1f96",
                    "stateRoot": "0x67a9fb631f4579f9015ef3c6f1f3830dfa2dc08afe156f750e90022134b9ebf6",
                    "timestamp": "0x627d9afa",
                    "totalDifficulty": "0xa55e1baf12dfa3fc50c",
                    // transactions have been left out of response
                    "transactions": [],
                    "transactionsRoot": "0x18a2978fc62cd1a23e90de920af68c0c3af3330327927cda4c005faccefb5ce7",
                    "uncles": ["0x817d4158df626cd8e9a20da9552c51a0d43f22b25de0b4dc5a089d81af899c70"]
                }
            }));
        });
    server
}

pub struct PeertestNode {
    pub enr: Enr,
    pub ipc_client: Client,
    pub rpc_handle: ServerHandle,
}

pub struct Peertest {
    pub bootnode: PeertestNode,
    pub nodes: Vec<PeertestNode>,
}

impl Peertest {
    pub fn exit_all_nodes(&self) {
        self.bootnode.rpc_handle.stop().unwrap();
        self.nodes
            .iter()
            .for_each(|node| node.rpc_handle.stop().unwrap());
    }
}

async fn launch_node(trin_config: TrinConfig) -> anyhow::Result<PeertestNode> {
    let web3_ipc_path = trin_config.web3_ipc_path.clone();
    let server = setup_mock_trusted_http_server();
    let mock_trusted_provider = TrustedProvider {
        http: surf::post(server.url("/")).into(),
    };
    let rpc_handle = trin::run_trin(trin_config, mock_trusted_provider)
        .await
        .unwrap();

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
    let discovery_port: u16 = 9000 + id;
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
                "--networks",
                "history,state",
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
                "--networks",
                "history,state",
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
