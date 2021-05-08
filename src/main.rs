#[macro_use]
extern crate lazy_static;
extern crate log;

mod cli;
use cli::TrinConfig;
mod jsonrpc;
use jsonrpc::launch_trin;
use log::info;
use std::env;
use std::time::Duration;

mod alexandria;
use alexandria::protocol::{AlexandriaProtocol, PortalConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let trin_config = TrinConfig::new();

    let infura_project_id = match env::var("TRIN_INFURA_PROJECT_ID") {
        Ok(val) => val,
        Err(_) => panic!(
            "Must supply Infura key as environment variable, like:\n\
            TRIN_INFURA_PROJECT_ID=\"your-key-here\" trin"
        ),
    };

    let web3_server_task = tokio::task::spawn_blocking(|| {
        launch_trin(trin_config, infura_project_id);
    });

    // TODO populate portal config from cli args
    let config: PortalConfig = Default::default();

    info!(
        "About to spawn portal p2p with boot nodes: {:?}",
        config.bootnode_enrs
    );
    tokio::spawn(async move {
        let _p2p = AlexandriaProtocol::new(config).await;
        // TODO next hacky test: make sure we establish a session with the boot node

        // TODO Probably some new API like p2p.maintain_network() that blocks forever
        tokio::time::sleep(Duration::from_secs(86400 * 365 * 10)).await;
    })
    .await
    .unwrap();

    web3_server_task.await.unwrap();
    Ok(())
}
