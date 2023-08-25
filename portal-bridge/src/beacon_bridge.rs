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
use ethportal_api::{BeaconContentKey, BeaconContentValue, LightClientUpdatesByRangeKey};
use ethportal_api::{BeaconNetworkApiClient, ContentValue};
use jsonrpsee::http_client::HttpClient;
use serde_json::Value;
use ssz::Encode;
use ssz_types::VariableList;
use std::cmp::Ordering;
use std::path::PathBuf;
use std::sync::atomic;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::thread::sleep;
use std::time::SystemTime;
use tracing::{info, warn};

pub struct BeaconBridge {
    pub api: ConsensusApi,
    mode: BridgeMode,
    portal_clients: Vec<HttpClient>,
}

impl BeaconBridge {
    pub fn new(api: ConsensusApi, mode: BridgeMode, portal_clients: Vec<HttpClient>) -> Self {
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
                &self.portal_clients,
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

        loop {
            let consensus_api = self.api.clone();
            let portal_clients = self.portal_clients.clone();
            let current_period = Arc::clone(&current_period);

            tokio::spawn(async move {
                Self::serve_latest(consensus_api, portal_clients, current_period).await;
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
        portal_clients: Vec<HttpClient>,
        current_period: Arc<AtomicUsize>,
    ) {
        // TODO: Serve LightClientBootstrap data

        // Serve `LightClientUpdate` data
        let api_clone = api.clone();
        let portal_clients_clone = portal_clients.clone();
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
        let portal_clients_clone = portal_clients.clone();
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

    #[allow(dead_code)] // FIXME: Remove this once we use it
    async fn serve_light_client_bootstrap(&self, block_root: String) -> anyhow::Result<()> {
        let data = self.api.get_lc_bootstrap(block_root).await?;
        let update: Value = serde_json::from_str(&data)?;
        let _: LightClientBootstrapCapella = serde_json::from_value(update["data"].clone())?;
        Ok(())
    }

    async fn serve_light_client_update(
        api: ConsensusApi,
        portal_clients: Vec<HttpClient>,
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
        match Self::gossip_beacon_content(&portal_clients, content_key, content_value).await {
            Ok(_) => {
                current_period.store(expected_current_period as usize, atomic::Ordering::Release);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    async fn serve_light_client_optimistic_update(
        api: ConsensusApi,
        portal_clients: Vec<HttpClient>,
    ) -> anyhow::Result<()> {
        let data = api.get_lc_optimistic_update().await?;
        let update: Value = serde_json::from_str(&data)?;

        let update: LightClientOptimisticUpdateCapella =
            serde_json::from_value(update["data"].clone())?;

        let mut content_bytes = ForkName::Capella.as_fork_digest().to_vec();
        content_bytes.append(&mut update.as_ssz_bytes());

        let content_value = BeaconContentValue::decode(&content_bytes)?;
        let content_key = BeaconContentKey::LightClientOptimisticUpdate(ZeroKey);
        info!(
            "Got lc optimistic update for slot {:?}",
            update.attested_header.beacon.slot
        );

        Self::gossip_beacon_content(&portal_clients, content_key, content_value).await
    }

    async fn serve_light_client_finality_update(
        api: ConsensusApi,
        portal_clients: Vec<HttpClient>,
    ) -> anyhow::Result<()> {
        let data = api.get_lc_finality_update().await?;
        let update: Value = serde_json::from_str(&data)?;
        let update: LightClientFinalityUpdateCapella =
            serde_json::from_value(update["data"].clone())?;

        let mut content_bytes = ForkName::Capella.as_fork_digest().to_vec();
        content_bytes.append(&mut update.as_ssz_bytes());

        let content_value = BeaconContentValue::decode(&content_bytes)?;
        let content_key = BeaconContentKey::LightClientFinalityUpdate(ZeroKey);
        info!(
            "Got lc finality update for slot {:?}",
            update.attested_header.beacon.slot
        );

        Self::gossip_beacon_content(&portal_clients, content_key, content_value).await
    }

    /// Gossip any given content key / value to the history network.
    async fn gossip_beacon_content(
        portal_clients: &Vec<HttpClient>,
        content_key: BeaconContentKey,
        content_value: BeaconContentValue,
    ) -> anyhow::Result<()> {
        for client in portal_clients {
            client
                .gossip(content_key.clone(), content_value.clone())
                .await?;
        }
        Ok(())
    }
}
