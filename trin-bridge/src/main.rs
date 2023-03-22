use ethportal_api::jsonrpsee::http_client::HttpClientBuilder;
use structopt::StructOpt;
use tokio::process::Command;
use tracing::info;
use trin_bridge::bridge::Bridge;
use trin_bridge::cli::{BridgeConfig, BridgeMode};
use trin_bridge::utils::generate_spaced_private_keys;
use trin_types::provider::{build_pandaops_http_client_from_env, TrustedProvider};
use trin_validation::accumulator::MasterAccumulator;
use trin_validation::oracle::HeaderOracle;

const PANDAOPS_URL: &str = "https://geth-lighthouse.mainnet.ethpandaops.io/";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let bridge_config = BridgeConfig::from_args();
    let private_keys = generate_spaced_private_keys(bridge_config.node_count as u8);
    let mut handles = vec![];
    let mut http_addresses = vec![];
    for (i, key) in private_keys.iter().enumerate() {
        let web3_http_address = format!("http://127.0.0.1:{}", 8545 + i);
        http_addresses.push(web3_http_address.clone());
        let discovery_port = format!("{}", 9000 + i);
        let handle = Command::new(bridge_config.executable_path.clone())
            .kill_on_drop(true)
            .args(["--kb", "0"])
            .args(["--unsafe-private-key", key])
            .args(["--web3-transport", "http"])
            .args(["--web3-http-address", &web3_http_address])
            .args(["--discovery-port", &discovery_port])
            //.args(["--bootnodes", "default"])
            .spawn()
            .expect("ls command failed to start");
        handles.push(handle);
    }
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    let trusted_provider = TrustedProvider {
        http: build_pandaops_http_client_from_env(PANDAOPS_URL.to_string()),
    };
    let master_acc =
        MasterAccumulator::try_from_file("../trin-validation/src/assets/merge_macc.bin".into())
            .unwrap();
    let header_oracle = HeaderOracle::new(trusted_provider, master_acc);

    let web3_clients = http_addresses
        .iter()
        .map(|address| HttpClientBuilder::default().build(address).unwrap())
        .collect();
    let bridge = Bridge {
        mode: bridge_config.mode,
        web3_clients,
        header_oracle,
        epoch_acc_path: bridge_config.epoch_acc_path,
    };

    info!("Launching bridge mode: {:?}", bridge.mode);
    match bridge.mode {
        BridgeMode::Latest => bridge.launch_latest().await,
        BridgeMode::Backfill => bridge.launch_backfill(None).await,
        BridgeMode::StartFromEpoch(epoch_number) => {
            bridge.launch_backfill(Some(epoch_number)).await
        }
    }
    Ok(())
}
