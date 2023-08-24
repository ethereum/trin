use crate::consensus_api::ConsensusApi;
use crate::constants::BEACON_GENESIS_TIME;
use crate::mode::BridgeMode;
use crate::utils::{
    duration_until_next_update, expected_current_slot, read_test_assets_from_file, TestAssets,
};
use anyhow::bail;
use ethportal_api::types::consensus::fork::ForkName;
use ethportal_api::types::consensus::light_client::bootstrap::LightClientBootstrapCapella;
use ethportal_api::types::consensus::light_client::finality_update::LightClientFinalityUpdateCapella;
use ethportal_api::types::consensus::light_client::optimistic_update::LightClientOptimisticUpdateCapella;
use ethportal_api::types::consensus::light_client::update::{
    LightClientUpdate, LightClientUpdateCapella,
};
use ethportal_api::types::content_key::beacon::ZeroKey;
use ethportal_api::types::content_value::beacon::{
    ForkVersionedLightClientUpdate, LightClientUpdatesByRange,
};
use ethportal_api::utils::bytes::hex_decode;
use ethportal_api::BeaconNetworkApiClient;
use ethportal_api::{
    BeaconContentKey, BeaconContentValue, LightClientBootstrapKey, LightClientUpdatesByRangeKey,
};
use jsonrpsee::http_client::HttpClient;
use serde_json::Value;
use ssz_types::VariableList;
use std::cmp::Ordering;
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::sync::{atomic, Mutex};
use std::thread::sleep;
use std::time::SystemTime;
use tracing::{info, warn};

pub struct BeaconBridge {
    pub api: ConsensusApi,
    mode: BridgeMode,
    portal_clients: Arc<Vec<HttpClient>>,
}

impl BeaconBridge {
    pub fn new(api: ConsensusApi, mode: BridgeMode, portal_clients: Arc<Vec<HttpClient>>) -> Self {
        Self {
            api,
            mode,
            portal_clients,
        }
    }

    pub async fn launch(&self) {
        info!("Launching beacon bridge mode: {:?}", self.mode);

        match self.mode.clone() {
            BridgeMode::Latest => self.launch_latest().await,
            BridgeMode::Test(test_path) => self.launch_test(test_path).await,
            other => panic!("Beacon bridge mode {other:?} not implemented!"),
        }

        info!("Bridge mode: {:?} complete.", self.mode);
    }

    async fn launch_test(&self, test_path: PathBuf) {
        let assets: TestAssets = read_test_assets_from_file(test_path);
        let assets = assets
            .into_beacon_assets()
            .expect("Error parsing beacon test assets.");

        for asset in assets.0.into_iter() {
            BeaconBridge::gossip_beacon_content(
                Arc::clone(&self.portal_clients),
                asset.content_key,
                asset.content_value,
            )
            .await
            .expect("Error serving beacon data in test mode.");
        }
    }

    ///  Get and serve the latest beacon data.
    async fn launch_latest(&self) {
        // Current sync committee period known by the bridge
        let current_period = Arc::new(AtomicUsize::new(0));
        let finalized_block_root = Arc::new(Mutex::new(String::new()));

        loop {
            let consensus_api = self.api.clone();
            let portal_clients = self.portal_clients.clone();
            let current_period = Arc::clone(&current_period);
            let finalized_block_root = Arc::clone(&finalized_block_root);

            tokio::spawn(async move {
                Self::serve_latest(
                    consensus_api,
                    portal_clients,
                    current_period,
                    finalized_block_root,
                )
                .await;
            });

            let now = SystemTime::now();

            let next_update = duration_until_next_update(BEACON_GENESIS_TIME, now)
                .to_std()
                .expect("failed to convert chrono duration to std duration");
            sleep(next_update);
        }
    }

    /// Serve latest beacon network data to the network
    async fn serve_latest(
        api: ConsensusApi,
        portal_clients: Arc<Vec<HttpClient>>,
        current_period: Arc<AtomicUsize>,
        finalized_block_root: Arc<Mutex<String>>,
    ) {
        // Serve LightClientBootstrap data
        let api_clone = api.clone();
        let portal_clients_clone = Arc::clone(&portal_clients);
        let finalized_block_root = Arc::clone(&finalized_block_root);

        tokio::spawn(async move {
            if let Err(err) = Self::serve_light_client_bootstrap(
                api_clone,
                portal_clients_clone,
                finalized_block_root,
            )
            .await
            {
                warn!("Failed to serve light client bootstrap: {err}");
            }
        });

        // Serve `LightClientUpdate` data
        let api_clone = api.clone();
        let portal_clients_clone = Arc::clone(&portal_clients);

        tokio::spawn(async move {
            if let Err(err) =
                Self::serve_light_client_update(api_clone, portal_clients_clone, current_period)
                    .await
            {
                warn!("Failed to serve light client update: {err}");
            }
        });

        // Serve `LightClientFinalityUpdate` data
        let api_clone = api.clone();
        let portal_clients_clone = Arc::clone(&portal_clients);
        tokio::spawn(async move {
            if let Err(err) =
                Self::serve_light_client_finality_update(api_clone, portal_clients_clone).await
            {
                warn!("Failed to serve light client finality update: {err}");
            }
        });

        // Serve `LightClientOptimisticUpdate` data
        tokio::spawn(async move {
            if let Err(err) = Self::serve_light_client_optimistic_update(api, portal_clients).await
            {
                warn!("Failed to serve light client optimistic update: {err}");
            }
        });
    }

    /// Serve `LightClientBootstrap` data
    async fn serve_light_client_bootstrap(
        api: ConsensusApi,
        portal_clients: Arc<Vec<HttpClient>>,
        finalized_block_root: Arc<Mutex<String>>,
    ) -> anyhow::Result<()> {
        let response = api.get_beacon_block_root("finalized".to_owned()).await?;
        let response: Value = serde_json::from_str(&response)?;
        let latest_finalized_block_root: String =
            serde_json::from_value(response["data"]["root"].clone())?;

        // If the latest finalized block root has changed, serve a new bootstrap
        if !finalized_block_root
            .lock()
            .expect("Failed to lock finalized block root")
            .eq(&latest_finalized_block_root)
        {
            let result = api.get_lc_bootstrap(&latest_finalized_block_root).await?;
            let result: Value = serde_json::from_str(&result)?;
            let bootstrap: LightClientBootstrapCapella =
                serde_json::from_value(result["data"].clone())?;

            info!(
                "Got lc bootstrap for slot {:?}",
                bootstrap.header.beacon.slot
            );

            let content_value = BeaconContentValue::LightClientBootstrap(bootstrap.into());
            let content_key = BeaconContentKey::LightClientBootstrap(LightClientBootstrapKey {
                block_hash: <[u8; 32]>::try_from(hex_decode(&latest_finalized_block_root)?)
                    .map_err(|err| {
                        anyhow::anyhow!("Failed to convert finalized block root to bytes: {err:?}")
                    })?,
            });

            // Update the latest finalized block root if we successfully gossiped the latest bootstrap.
            match Self::gossip_beacon_content(portal_clients, content_key, content_value).await {
                Ok(_) => {
                    let mut finalized_block_root = finalized_block_root
                        .lock()
                        .expect("Unable to lock finalized block root");
                    *finalized_block_root = latest_finalized_block_root;
                }
                Err(err) => return Err(err),
            }
        }

        Ok(())
    }

    async fn serve_light_client_update(
        api: ConsensusApi,
        portal_clients: Arc<Vec<HttpClient>>,
        current_period: Arc<AtomicUsize>,
    ) -> anyhow::Result<()> {
        let now = SystemTime::now();
        let expected_current_period = expected_current_slot(BEACON_GENESIS_TIME, now) / (32 * 256);
        match (expected_current_period as usize)
            .cmp(&current_period.load(atomic::Ordering::Acquire))
        {
            Ordering::Equal => {
                // We already gossiped the latest data from the current period, no need to serve it again.
                return Ok(());
            }
            Ordering::Less => {
                // if we panic here, it is a bug
                bail!("System clock went backwards: Expected current period is less than known period");
            }
            Ordering::Greater => {
                // Continue
            }
        }

        let data = api.get_lc_updates(expected_current_period, 1).await?;
        let update: Value = serde_json::from_str(&data)?;
        let update: LightClientUpdateCapella = serde_json::from_value(update[0]["data"].clone())?;
        let fork_versioned_update = ForkVersionedLightClientUpdate {
            fork_name: ForkName::Capella,
            update: LightClientUpdate::Capella(update.clone()),
        };

        let content_value = BeaconContentValue::LightClientUpdatesByRange(
            LightClientUpdatesByRange(VariableList::from(vec![fork_versioned_update])),
        );
        let content_key =
            BeaconContentKey::LightClientUpdatesByRange(LightClientUpdatesByRangeKey {
                start_period: expected_current_period,
                count: 1,
            });
        info!(
            "Got lc update for slot {:?}",
            update.attested_header.beacon.slot
        );

        // Update the current known period if we successfully gossiped the latest data.
        match Self::gossip_beacon_content(portal_clients, content_key, content_value).await {
            Ok(_) => {
                current_period.store(expected_current_period as usize, atomic::Ordering::Release);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    async fn serve_light_client_optimistic_update(
        api: ConsensusApi,
        portal_clients: Arc<Vec<HttpClient>>,
    ) -> anyhow::Result<()> {
        let data = api.get_lc_optimistic_update().await?;
        let update: Value = serde_json::from_str(&data)?;

        let update: LightClientOptimisticUpdateCapella =
            serde_json::from_value(update["data"].clone())?;
        info!(
            "Got lc optimistic update for slot {:?}",
            update.attested_header.beacon.slot
        );
        let content_value = BeaconContentValue::LightClientOptimisticUpdate(update.into());
        let content_key = BeaconContentKey::LightClientOptimisticUpdate(ZeroKey);

        Self::gossip_beacon_content(portal_clients, content_key, content_value).await
    }

    async fn serve_light_client_finality_update(
        api: ConsensusApi,
        portal_clients: Arc<Vec<HttpClient>>,
    ) -> anyhow::Result<()> {
        let data = api.get_lc_finality_update().await?;
        let update: Value = serde_json::from_str(&data)?;
        let update: LightClientFinalityUpdateCapella =
            serde_json::from_value(update["data"].clone())?;
        info!(
            "Got lc finality update for slot {:?}",
            update.attested_header.beacon.slot
        );
        let content_value = BeaconContentValue::LightClientFinalityUpdate(update.into());
        let content_key = BeaconContentKey::LightClientFinalityUpdate(ZeroKey);

        Self::gossip_beacon_content(portal_clients, content_key, content_value).await
    }

    /// Gossip any given content key / value to the history network.
    async fn gossip_beacon_content(
        portal_clients: Arc<Vec<HttpClient>>,
        content_key: BeaconContentKey,
        content_value: BeaconContentValue,
    ) -> anyhow::Result<()> {
        for client in portal_clients.as_ref() {
            client
                .gossip(content_key.clone(), content_value.clone())
                .await?;
        }
        Ok(())
    }
}
