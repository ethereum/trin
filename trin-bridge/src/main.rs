use ethportal_api::jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use structopt::StructOpt;
use tokio::process::Command;
use tokio::time::{sleep, Duration};
use tracing::info;
use trin_bridge::bridge::Bridge;
use trin_bridge::cli::{BridgeConfig, BridgeMode};
use trin_bridge::constants::PANDAOPS_URL;
use trin_bridge::utils::generate_spaced_private_keys;
use trin_types::provider::{build_pandaops_http_client_from_env, TrustedProvider};
use trin_validation::accumulator::MasterAccumulator;
use trin_validation::oracle::HeaderOracle;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let bridge_config = BridgeConfig::from_args();
    let private_keys = generate_spaced_private_keys(bridge_config.node_count);
    let mut handles = vec![];
    let mut http_addresses = vec![];
    for (i, key) in private_keys.iter().enumerate() {
        let web3_http_address = format!("http://127.0.0.1:{}", 8545 + i);
        let discovery_port = format!("{}", 9000 + i);
        let handle = Command::new(bridge_config.executable_path.clone())
            .kill_on_drop(true)
            .args(["--kb", "0"])
            .args(["--unsafe-private-key", key])
            .args(["--web3-transport", "http"])
            .args(["--web3-http-address", &web3_http_address])
            .args(["--discovery-port", &discovery_port])
            .args(["--bootnodes", "default"])
            .spawn()
            .expect("failed to spawn trin process");
        http_addresses.push(web3_http_address);
        handles.push(handle);
    }
    sleep(Duration::from_secs(5)).await;

    let trusted_provider = TrustedProvider {
        http: build_pandaops_http_client_from_env(PANDAOPS_URL.to_string()),
    };
    let master_acc =
        MasterAccumulator::try_from_file("../trin-validation/src/assets/merge_macc.bin".into())?;
    let header_oracle = HeaderOracle::new(trusted_provider, master_acc);

    let portal_clients: Result<Vec<HttpClient>, String> = http_addresses
        .iter()
        .map(|address| {
            HttpClientBuilder::default()
                .build(address)
                .map_err(|e| e.to_string())
        })
        .collect();
    let bridge = Bridge {
        mode: bridge_config.mode,
        portal_clients: portal_clients?,
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
