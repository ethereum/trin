use ethportal_api::BeaconContentKey;
use light_client::config::networks;
use light_client::consensus::rpc::portal_rpc::PortalRpc;
use light_client::database::FileDB;
use light_client::{Client, ClientBuilder};
use portalnet::overlay_service::OverlayCommand;
use std::path::PathBuf;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{error, info};

#[derive(Clone, Debug)]
pub struct BeaconSync {
    pub overlay_tx: UnboundedSender<OverlayCommand<BeaconContentKey>>,
}

impl BeaconSync {
    pub fn new(overlay_tx: UnboundedSender<OverlayCommand<BeaconContentKey>>) -> Self {
        Self { overlay_tx }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        // Create a new Light Client Builder
        let mut builder = ClientBuilder::new();

        // Set the network to mainnet
        builder = builder.network(networks::Network::Mainnet);

        // Set the checkpoint to the last known checkpoint
        builder = builder
            .checkpoint("0x44389a44d9da9e5e073a7f0bfb19844c2a9aacfafaa81558577ae0e373ec9eb9");

        // Set the data dir
        builder = builder.data_dir(PathBuf::from("/tmp/portal-light-client"));

        // Build Portal rpc
        let portal_rpc = PortalRpc::with_portal(self.overlay_tx.clone());

        // Build the client
        let mut client: Client<FileDB, PortalRpc> = builder
            .build_with_rpc(portal_rpc)
            .expect("Failed to build portal light client");

        // Run the client
        loop {
            info!("Starting syncing portal light client...");
            match client.start().await {
                Ok(_) => break,
                Err(e) => {
                    error!("Error syncing portal light client: {e} Retrying...");
                }
            }
        }

        Ok(())
    }
}
