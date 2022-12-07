pub mod cli;
pub mod jsonrpc;
pub mod scenarios;

pub use cli::PeertestConfig;
pub use jsonrpc::get_enode;

use std::net::{IpAddr, Ipv4Addr};
use std::{sync::Arc, thread, time};

use futures::future;
use httpmock::prelude::{MockServer, POST};
use serde_json::json;

use trin_core::{
    cli::TrinConfig, jsonrpc::service::JsonRpcExiter, portalnet::types::messages::SszEnr,
    utils::provider::TrustedProvider,
};

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

#[derive(Clone, Debug)]
pub enum TransportProtocol {
    IPC,
    HTTP,
}

#[derive(Clone, Debug)]
pub enum Web3Transport {
    IPC(IpcTransport),
    HTTP(HttpTransport),
}

#[derive(Clone, Debug)]
pub struct IpcTransport {
    pub ipc_path: String,
}

#[derive(Clone, Debug)]
pub struct HttpTransport {
    pub address: String,
}

pub struct PeertestNode {
    pub enr: SszEnr,
    pub transport: Web3Transport,
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

pub async fn launch_node(
    trin_config: TrinConfig,
    transport_protocol: TransportProtocol,
) -> anyhow::Result<PeertestNode> {
    let server = setup_mock_trusted_http_server();
    let mock_trusted_provider = TrustedProvider {
        http: ureq::post(&server.url("/")),
        ws: None,
    };
    let transport = match transport_protocol {
        TransportProtocol::IPC => Web3Transport::IPC(IpcTransport {
            ipc_path: trin_config.web3_ipc_path.to_string(),
        }),
        TransportProtocol::HTTP => Web3Transport::HTTP(HttpTransport {
            address: trin_config.web3_http_address.to_string(),
        }),
    };
    let exiter = trin::run_trin(trin_config, mock_trusted_provider)
        .await
        .unwrap();
    let enr = get_enode(transport.clone()).await?;

    // Short sleep to make sure all peertest nodes can connect
    thread::sleep(time::Duration::from_secs(2));
    Ok(PeertestNode {
        enr,
        transport,
        exiter,
    })
}

fn generate_trin_config(
    id: u16,
    bootnode_enr: Option<&SszEnr>,
    transport_protocol: TransportProtocol,
) -> TrinConfig {
    let discovery_port: u16 = 9000 + id;
    let discovery_port: String = discovery_port.to_string();
    // This specific private key scheme is chosen to enforce that the first peer node will be in
    // the 256 kbucket of the bootnode, to ensure consistent `FindNodes` tests.
    let mut private_key = vec![id as u8; 3];
    private_key.append(&mut vec![0u8; 29]);
    let private_key = hex::encode(private_key);
    let mut trin_config_args: Vec<String> = vec![
        "trin".to_owned(),
        "--networks".to_owned(),
        "history,state".to_owned(),
        "--discovery-port".to_owned(),
        discovery_port.to_owned(),
        "--unsafe-private-key".to_owned(),
        private_key,
        "--ephemeral".to_owned(),
    ];
    match bootnode_enr {
        Some(enr) => {
            let external_addr = format!(
                "{}:{}",
                enr.ip4().expect("bootnode must have IP"),
                discovery_port
            );
            let enr_base64 = enr.to_base64();
            trin_config_args.push("--external-address".to_owned());
            trin_config_args.push(external_addr);
            trin_config_args.push("--bootnodes".to_owned());
            trin_config_args.push(enr_base64);
        }
        None => {
            let ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
            let external_addr = format!("{}:{}", ip_addr, discovery_port);
            trin_config_args.push("--external-address".to_owned());
            trin_config_args.push(external_addr);
        }
    };

    match transport_protocol {
        TransportProtocol::IPC => {
            let web3_ipc_path = format!("/tmp/ethportal-peertest-buddy-{id}.ipc");
            trin_config_args.push("--web3-ipc-path".to_owned());
            trin_config_args.push(web3_ipc_path);
        }
        TransportProtocol::HTTP => {
            trin_config_args.push("--web3-transport".to_owned());
            trin_config_args.push("http".to_owned());
            // 8545 is reserved for test node, so we start @ 8546 & increment
            let http_port = 8545 + id;
            let web3_http_address = format!("127.0.0.1:{http_port}");
            trin_config_args.push("--web3-http-address".to_owned());
            trin_config_args.push(web3_http_address);
        }
    }
    TrinConfig::new_from(trin_config_args.iter()).unwrap()
}

pub async fn launch_peertest_nodes(count: u16, transport_protocol: TransportProtocol) -> Peertest {
    // Bootnode uses a peertest id of 1
    let bootnode_config = generate_trin_config(1, None, transport_protocol.clone());
    let bootnode = launch_node(bootnode_config, transport_protocol.clone())
        .await
        .unwrap();
    let bootnode_enr = &bootnode.enr;
    // All other peertest node ids begin at 2, and increment from there
    let nodes = future::try_join_all((2..count + 1).into_iter().map(|id| {
        let node_config = generate_trin_config(id, Some(bootnode_enr), transport_protocol.clone());
        launch_node(node_config, transport_protocol.clone())
    }))
    .await
    .unwrap();
    Peertest { bootnode, nodes }
}
