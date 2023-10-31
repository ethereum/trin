use std::cmp::Ordering;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use anyhow::bail;
use jsonrpsee::http_client::HttpClient;
use serde_json::Value;
use ssz_types::VariableList;
use tokio::time::{interval, sleep, Duration, MissedTickBehavior};
use tracing::{info, warn};

use crate::consensus_api::ConsensusApi;
use crate::constants::BEACON_GENESIS_TIME;
use crate::mode::BridgeMode;
use crate::stats::{BeaconSlotStats, StatsReporter};
use crate::utils::{
    duration_until_next_update, expected_current_slot, read_test_assets_from_file, TestAssets,
};
use ethportal_api::types::consensus::fork::ForkName;
use ethportal_api::types::consensus::light_client::bootstrap::LightClientBootstrapCapella;
use ethportal_api::types::consensus::light_client::finality_update::LightClientFinalityUpdateCapella;
use ethportal_api::types::consensus::light_client::optimistic_update::LightClientOptimisticUpdateCapella;
use ethportal_api::types::consensus::light_client::update::{
    LightClientUpdate, LightClientUpdateCapella,
};
use ethportal_api::types::content_key::beacon::{
    LightClientFinalityUpdateKey, LightClientOptimisticUpdateKey,
};
use ethportal_api::types::content_value::beacon::{
    ForkVersionedLightClientUpdate, LightClientUpdatesByRange,
};
use ethportal_api::utils::bytes::hex_decode;
use ethportal_api::BeaconNetworkApiClient;
use ethportal_api::{
    BeaconContentKey, BeaconContentValue, LightClientBootstrapKey, LightClientUpdatesByRangeKey,
};

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

        // test files have no slot number data, so report all gossiped content at height 0.
        let slot_stats = Arc::new(Mutex::new(BeaconSlotStats::new(0)));
        for asset in assets.0.into_iter() {
            BeaconBridge::gossip_beacon_content(
                Arc::clone(&self.portal_clients),
                asset.content_key,
                asset.content_value,
                slot_stats.clone(),
            )
            .await
            .expect("Error serving beacon data in test mode.");
        }
    }

    ///  Get and serve the latest beacon data.
    async fn launch_latest(&self) {
        // Current sync committee period known by the bridge
        let (mut current_period, mut finalized_block_root, mut finalized_slot) =
            Self::serve_latest(
                self.api.clone(),
                self.portal_clients.clone(),
                0,
                String::new(),
                0,
            )
            .await;

        // Sleep until next update becomes available. This sets up the interval to update as soon as
        // the following slot becomes available.
        let now = SystemTime::now();
        let next_update = duration_until_next_update(BEACON_GENESIS_TIME, now)
            .to_std()
            .expect("failed to convert chrono duration to std duration");
        sleep(next_update).await;

        // Run the beacon bridge update once every slot
        let mut interval = interval(Duration::from_secs(12));
        // If serving takes a little too long, then we want to serve the next one as soon as
        // possible, but not serve any extras until the following slot. "Skip" gets this behavior.
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            let consensus_api = self.api.clone();
            let portal_clients = self.portal_clients.clone();

            (current_period, finalized_block_root, finalized_slot) = Self::serve_latest(
                consensus_api,
                portal_clients,
                current_period,
                finalized_block_root,
                finalized_slot,
            )
            .await;

            interval.tick().await;
        }
    }

    /// Serve latest beacon network data to the network
    ///
    /// Returns the new current period and finalized block root
    async fn serve_latest(
        api: ConsensusApi,
        portal_clients: Arc<Vec<HttpClient>>,
        current_period: u64,
        finalized_block_root: String,
        finalized_slot: u64,
    ) -> (u64, String, u64) {
        // Serve LightClientBootstrap data
        let api_clone = api.clone();
        let portal_clients_clone = Arc::clone(&portal_clients);
        let slot_stats = Arc::new(Mutex::new(BeaconSlotStats::new(finalized_slot)));

        let slot_stats_clone = slot_stats.clone();
        let bootstrap_result = tokio::spawn(async move {
            Self::serve_light_client_bootstrap(
                api_clone,
                portal_clients_clone,
                &finalized_block_root,
                slot_stats_clone,
            )
            .await
            .or_else(|err| {
                warn!("Failed to serve light client bootstrap: {err}");
                Ok::<String, ()>(finalized_block_root)
            })
            .expect("always return the original or new finalized block root")
        });

        // Serve `LightClientUpdate` data
        let api_clone = api.clone();
        let portal_clients_clone = Arc::clone(&portal_clients);

        let slot_stats_clone = slot_stats.clone();
        let update_result = tokio::spawn(async move {
            Self::serve_light_client_update(
                api_clone,
                portal_clients_clone,
                current_period,
                slot_stats_clone,
            )
            .await
            .or_else(|err| {
                warn!("Failed to serve light client update: {err}");
                Ok::<u64, ()>(current_period)
            })
            .expect("always return the original or new period")
        });

        // Serve `LightClientFinalityUpdate` data
        let api_clone = api.clone();
        let portal_clients_clone = Arc::clone(&portal_clients);
        let slot_stats_clone = slot_stats.clone();
        let finalized_slot = tokio::spawn(async move {
            Self::serve_light_client_finality_update(
                api_clone,
                portal_clients_clone,
                finalized_slot,
                slot_stats_clone,
            )
            .await
            .or_else(|err| {
                warn!("Failed to serve light client finality update: {err}");
                Ok::<u64, ()>(finalized_slot)
            })
            .expect("always return the original or new finalized slot")
        });

        // Serve `LightClientOptimisticUpdate` data
        let slot_stats_clone = slot_stats.clone();
        let optimistic_update = tokio::spawn(async move {
            if let Err(err) =
                Self::serve_light_client_optimistic_update(api, portal_clients, slot_stats_clone)
                    .await
            {
                warn!("Failed to serve light client optimistic update: {err}");
            }
        });

        let new_period = update_result.await.expect("update task is never cancelled");
        let new_finalized_block_root = bootstrap_result
            .await
            .expect("bootstrap task is never cancelled");
        let finalized_slot = finalized_slot
            .await
            .expect("finality update task is never cancelled");
        optimistic_update
            .await
            .expect("optimistic update task is never cancelled");
        if let Ok(stats) = slot_stats.lock() {
            stats.report();
        } else {
            warn!("Error displaying beacon gossip stats. Unable to acquire lock.");
        };
        (new_period, new_finalized_block_root, finalized_slot)
    }

    /// Serve `LightClientBootstrap` data
    async fn serve_light_client_bootstrap(
        api: ConsensusApi,
        portal_clients: Arc<Vec<HttpClient>>,
        finalized_block_root: &str,
        slot_stats: Arc<Mutex<BeaconSlotStats>>,
    ) -> anyhow::Result<String> {
        let response = api.get_beacon_block_root("finalized".to_owned()).await?;
        let response: Value = serde_json::from_str(&response)?;
        let latest_finalized_block_root: String =
            serde_json::from_value(response["data"]["root"].clone())?;

        // If the latest finalized block root is the same, return as unchanged
        if finalized_block_root.eq(&latest_finalized_block_root) {
            return Ok(latest_finalized_block_root);
        }

        // finalized block root is different, so serve a new bootstrap
        let result = api.get_lc_bootstrap(&latest_finalized_block_root).await?;
        let result: Value = serde_json::from_str(&result)?;
        let bootstrap: LightClientBootstrapCapella =
            serde_json::from_value(result["data"].clone())?;

        info!(
            header_slot=%bootstrap.header.beacon.slot,
            "Generated LightClientBootstrap",
        );

        let content_value = BeaconContentValue::LightClientBootstrap(bootstrap.into());
        let content_key = BeaconContentKey::LightClientBootstrap(LightClientBootstrapKey {
            block_hash: <[u8; 32]>::try_from(hex_decode(&latest_finalized_block_root)?).map_err(
                |err| anyhow::anyhow!("Failed to convert finalized block root to bytes: {err:?}"),
            )?,
        });

        // Return the latest finalized block root if we successfully gossiped the latest bootstrap.
        Self::gossip_beacon_content(portal_clients, content_key, content_value, slot_stats)
            .await
            .map(|_| latest_finalized_block_root)
    }

    async fn serve_light_client_update(
        api: ConsensusApi,
        portal_clients: Arc<Vec<HttpClient>>,
        current_period: u64,
        slot_stats: Arc<Mutex<BeaconSlotStats>>,
    ) -> anyhow::Result<u64> {
        let now = SystemTime::now();
        let expected_current_period = expected_current_slot(BEACON_GENESIS_TIME, now) / (32 * 256);
        match expected_current_period.cmp(&current_period) {
            Ordering::Equal => {
                // We already gossiped the latest data from the current period, no need to serve it again.
                return Ok(current_period);
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
            period = %expected_current_period,
            "Generated LightClientUpdate",
        );

        // Update the current known period if we successfully gossiped the latest data.
        Self::gossip_beacon_content(portal_clients, content_key, content_value, slot_stats).await?;

        Ok(expected_current_period)
    }

    async fn serve_light_client_optimistic_update(
        api: ConsensusApi,
        portal_clients: Arc<Vec<HttpClient>>,
        slot_stats: Arc<Mutex<BeaconSlotStats>>,
    ) -> anyhow::Result<()> {
        let data = api.get_lc_optimistic_update().await?;
        let update: Value = serde_json::from_str(&data)?;

        let update: LightClientOptimisticUpdateCapella =
            serde_json::from_value(update["data"].clone())?;
        info!(
            signature_slot = %update.signature_slot,
            "Generated LightClientOptimisticUpdate",
        );
        let content_key = BeaconContentKey::LightClientOptimisticUpdate(
            LightClientOptimisticUpdateKey::new(update.signature_slot),
        );
        let content_value = BeaconContentValue::LightClientOptimisticUpdate(update.into());
        Self::gossip_beacon_content(portal_clients, content_key, content_value, slot_stats).await
    }

    async fn serve_light_client_finality_update(
        api: ConsensusApi,
        portal_clients: Arc<Vec<HttpClient>>,
        finalized_slot: u64,
        slot_stats: Arc<Mutex<BeaconSlotStats>>,
    ) -> anyhow::Result<u64> {
        let data = api.get_lc_finality_update().await?;
        let update: Value = serde_json::from_str(&data)?;
        let update: LightClientFinalityUpdateCapella =
            serde_json::from_value(update["data"].clone())?;
        info!(
            finalized_slot = %update.finalized_header.beacon.slot,
            "Generated LightClientFinalityUpdate",
        );

        let new_finalized_slot = update.finalized_header.beacon.slot;

        match new_finalized_slot.cmp(&finalized_slot) {
            Ordering::Equal => {
                // We already gossiped the latest finality updated with the same finalized slot, no need to serve it again.
                return Ok(finalized_slot);
            }
            Ordering::Less => {
                // if we panic here, it is a bug
                bail!("Consensus client must not unwind finalized block, but: New finalized slot is less than known finalized slot");
            }
            Ordering::Greater => {
                // Continue
            }
        }

        let content_key = BeaconContentKey::LightClientFinalityUpdate(
            LightClientFinalityUpdateKey::new(new_finalized_slot),
        );
        let content_value = BeaconContentValue::LightClientFinalityUpdate(update.into());

        Self::gossip_beacon_content(portal_clients, content_key, content_value, slot_stats).await?;

        Ok(new_finalized_slot)
    }

    /// Gossip any given content key / value to the history network.
    async fn gossip_beacon_content(
        portal_clients: Arc<Vec<HttpClient>>,
        content_key: BeaconContentKey,
        content_value: BeaconContentValue,
        slot_stats: Arc<Mutex<BeaconSlotStats>>,
    ) -> anyhow::Result<()> {
        let mut results = vec![];
        for client in portal_clients.as_ref() {
            let result = client
                .trace_gossip(content_key.clone(), content_value.clone())
                .await;
            results.push(result);
        }
        if let Ok(mut data) = slot_stats.lock() {
            data.update(content_key, results.into());
        } else {
            warn!("Error updating beacon gossip stats. Unable to acquire lock.");
        }
        Ok(())
    }
}
