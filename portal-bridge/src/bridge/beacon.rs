use std::sync::Mutex as StdMutex;

use anyhow::{bail, ensure};
use jsonrpsee::http_client::HttpClient;
use serde_json::Value;
use ssz_types::VariableList;
use std::{cmp::Ordering, path::PathBuf, sync::Arc, time::SystemTime};
use tokio::{
    sync::Mutex,
    time::{interval, sleep, Duration, MissedTickBehavior},
};
use tracing::{info, warn, Instrument};
use trin_metrics::bridge::BridgeMetricsReporter;

use crate::{
    api::consensus::ConsensusApi,
    constants::BEACON_GENESIS_TIME,
    gossip::gossip_beacon_content,
    stats::{BeaconSlotStats, StatsReporter},
    types::mode::BridgeMode,
    utils::{
        duration_until_next_update, expected_current_slot, read_test_assets_from_file, TestAssets,
    },
};
use ethportal_api::{
    consensus::{
        beacon_state::BeaconStateDeneb,
        historical_summaries::{HistoricalSummariesStateProof, HistoricalSummariesWithProof},
    },
    light_client::{
        bootstrap::LightClientBootstrapDeneb,
        finality_update::LightClientFinalityUpdateDeneb,
        optimistic_update::LightClientOptimisticUpdateDeneb,
        update::{LightClientUpdate, LightClientUpdateDeneb},
    },
    types::{
        consensus::fork::ForkName,
        content_key::beacon::{
            HistoricalSummariesWithProofKey, LightClientFinalityUpdateKey,
            LightClientOptimisticUpdateKey,
        },
        content_value::beacon::{
            ForkVersionedHistoricalSummariesWithProof, ForkVersionedLightClientUpdate,
            LightClientUpdatesByRange,
        },
    },
    utils::bytes::hex_decode,
    BeaconContentKey, BeaconContentValue, LightClientBootstrapKey, LightClientUpdatesByRangeKey,
};

/// The number of slots in an epoch.
const SLOTS_PER_EPOCH: u64 = 32;
/// The number of slots in a sync committee period.
const SLOTS_PER_PERIOD: u64 = SLOTS_PER_EPOCH * 256;
/// The historical summaries proof always has a length of 5 hashes.
const HISTORICAL_SUMMARIES_PROOF_LENGTH: usize = 5;

/// A helper struct to hold the finalized beacon state metadata.
#[derive(Clone, Debug, Default)]
pub struct FinalizedBeaconState {
    /// THe root of the finalized state
    pub state_root: String,
    /// True if the beacon state download is in progress
    pub in_progress: bool,
}

impl FinalizedBeaconState {
    pub fn new() -> Self {
        Self::default()
    }
}

pub struct BeaconBridge {
    pub api: ConsensusApi,
    mode: BridgeMode,
    portal_client: HttpClient,
    pub metrics: BridgeMetricsReporter,
}

impl BeaconBridge {
    pub fn new(api: ConsensusApi, mode: BridgeMode, portal_client: HttpClient) -> Self {
        let metrics = BridgeMetricsReporter::new("beacon".to_string(), &format!("{mode:?}"));
        Self {
            api,
            mode,
            portal_client,
            metrics,
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
        let slot_stats = Arc::new(StdMutex::new(BeaconSlotStats::new(0)));
        for asset in assets.0.into_iter() {
            gossip_beacon_content(
                self.portal_client.clone(),
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
        let current_period = Arc::new(Mutex::new(0));
        let finalized_block_root = Arc::new(Mutex::new(String::new()));
        let finalized_slot = Arc::new(Mutex::new(0));
        let finalized_state_root = Arc::new(Mutex::new(FinalizedBeaconState::new()));

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
            interval.tick().await;

            let consensus_api = self.api.clone();
            let portal_client = self.portal_client.clone();

            Self::serve_latest(
                consensus_api,
                portal_client,
                current_period.clone(),
                finalized_block_root.clone(),
                finalized_slot.clone(),
                finalized_state_root.clone(),
            )
            .await;
        }
    }

    /// Serve latest beacon network data to the network
    ///
    /// Returns the new current period and finalized block root
    async fn serve_latest(
        api: ConsensusApi,
        portal_client: HttpClient,
        current_period: Arc<Mutex<u64>>,
        finalized_block_root: Arc<Mutex<String>>,
        finalized_slot: Arc<Mutex<u64>>,
        finalized_state_root: Arc<Mutex<FinalizedBeaconState>>,
    ) {
        // Serve LightClientBootstrap data
        let api_clone = api.clone();
        let slot_stats = Arc::new(StdMutex::new(BeaconSlotStats::new(
            *finalized_slot.lock().await,
        )));

        let slot_stats_clone = slot_stats.clone();
        let portal_client_clone = portal_client.clone();

        tokio::spawn(async move {
            if let Err(err) = Self::serve_light_client_bootstrap(
                api_clone,
                portal_client_clone,
                &finalized_block_root,
                slot_stats_clone,
            )
            .in_current_span()
            .await
            {
                warn!("Failed to serve LightClientBootstrap: {err}");
            }
        });

        // Serve `LightClientUpdate` data
        let api_clone = api.clone();

        let slot_stats_clone = slot_stats.clone();
        let portal_client_clone = portal_client.clone();
        tokio::spawn(async move {
            if let Err(err) = Self::serve_light_client_update(
                api_clone,
                portal_client_clone,
                current_period,
                slot_stats_clone,
            )
            .in_current_span()
            .await
            {
                warn!("Failed to serve LightClientUpdate: {err}");
            }
        });

        // Serve `LightClientFinalityUpdate` data
        let api_clone = api.clone();
        let slot_stats_clone = slot_stats.clone();
        let portal_client_clone = portal_client.clone();
        tokio::spawn(async move {
            if let Err(err) = Self::serve_light_client_finality_update(
                api_clone,
                portal_client_clone,
                finalized_slot,
                slot_stats_clone,
            )
            .in_current_span()
            .await
            {
                warn!("Failed to serve LightClientFinalityUpdate: {err}");
            }
        });

        // Serve `LightClientOptimisticUpdate` data
        let api_clone = api.clone();
        let slot_stats_clone = slot_stats.clone();
        let portal_client_clone = portal_client.clone();
        tokio::spawn(async move {
            if let Err(err) = Self::serve_light_client_optimistic_update(
                api_clone,
                portal_client_clone,
                slot_stats_clone,
            )
            .in_current_span()
            .await
            {
                warn!("Failed to serve LightClientOptimisticUpdate: {err}");
            }
        });

        // Serve `HistoricalSummariesWithProof` data
        let slot_stats_clone = slot_stats.clone();
        tokio::spawn(async move {
            if let Err(err) = Self::serve_historical_summaries_with_proof(
                api,
                portal_client,
                slot_stats_clone,
                finalized_state_root.clone(),
            )
            .in_current_span()
            .await
            {
                finalized_state_root.lock().await.in_progress = false;
                warn!("Failed to serve HistoricalSummariesWithProof: {err}");
            }
        });

        if let Ok(stats) = slot_stats.lock() {
            stats.report();
        } else {
            warn!("Error displaying beacon gossip stats. Unable to acquire lock.");
        };
    }

    /// Serve `LightClientBootstrap` data
    async fn serve_light_client_bootstrap(
        api: ConsensusApi,
        portal_client: HttpClient,
        finalized_block_root: &Arc<Mutex<String>>,
        slot_stats: Arc<StdMutex<BeaconSlotStats>>,
    ) -> anyhow::Result<()> {
        let response = api.get_beacon_block_root("finalized".to_owned()).await?;
        let response: Value = serde_json::from_str(&response)?;
        let latest_finalized_block_root: String =
            serde_json::from_value(response["data"]["root"].clone())?;

        // If the latest finalized block root is the same, do not serve a new bootstrap
        if latest_finalized_block_root.eq(&*finalized_block_root.lock().await) {
            return Ok(());
        }

        // finalized block root is different, so serve a new bootstrap
        let result = api.get_lc_bootstrap(&latest_finalized_block_root).await?;
        let result: Value = serde_json::from_str(&result)?;
        let bootstrap: LightClientBootstrapDeneb = serde_json::from_value(result["data"].clone())?;

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
        gossip_beacon_content(portal_client, content_key, content_value, slot_stats).await?;
        *finalized_block_root.lock().await = latest_finalized_block_root;

        Ok(())
    }

    async fn serve_light_client_update(
        api: ConsensusApi,
        portal_client: HttpClient,
        current_period: Arc<Mutex<u64>>,
        slot_stats: Arc<StdMutex<BeaconSlotStats>>,
    ) -> anyhow::Result<()> {
        let now = SystemTime::now();
        let expected_current_period =
            expected_current_slot(BEACON_GENESIS_TIME, now) / SLOTS_PER_PERIOD;
        match expected_current_period.cmp(&*current_period.lock().await) {
            Ordering::Equal => {
                // We already gossiped the latest data from the current period, no need to serve it
                // again.
                return Ok(());
            }
            Ordering::Less => {
                // if we panic here, it is a bug
                bail!("Expected current period is less than known period");
            }
            Ordering::Greater => {
                // Continue
            }
        }

        let data = api.get_lc_updates(expected_current_period, 1).await?;
        let update: Value = serde_json::from_str(&data)?;
        let update: LightClientUpdateDeneb = serde_json::from_value(update[0]["data"].clone())?;
        let finalized_header_period = update.finalized_header.beacon.slot / SLOTS_PER_PERIOD;

        // We don't serve a `LightClientUpdate` if its finalized header slot is not within the
        // expected current period.
        if finalized_header_period != expected_current_period {
            warn!(
                "LightClientUpdate finalized header is not for the expected period: Expected: {expected_current_period}, Actual: {actual_period}",
                expected_current_period = expected_current_period,
                actual_period = finalized_header_period
            );
            return Ok(());
        }

        let fork_versioned_update = ForkVersionedLightClientUpdate {
            fork_name: ForkName::Deneb,
            update: LightClientUpdate::Deneb(update.clone()),
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
        gossip_beacon_content(portal_client, content_key, content_value, slot_stats).await?;
        *current_period.lock().await = expected_current_period;

        Ok(())
    }

    async fn serve_light_client_optimistic_update(
        api: ConsensusApi,
        portal_client: HttpClient,
        slot_stats: Arc<StdMutex<BeaconSlotStats>>,
    ) -> anyhow::Result<()> {
        let data = api.get_lc_optimistic_update().await?;
        let update: Value = serde_json::from_str(&data)?;

        let update: LightClientOptimisticUpdateDeneb =
            serde_json::from_value(update["data"].clone())?;
        info!(
            signature_slot = %update.signature_slot,
            "Generated LightClientOptimisticUpdate",
        );
        let content_key = BeaconContentKey::LightClientOptimisticUpdate(
            LightClientOptimisticUpdateKey::new(update.signature_slot),
        );
        let content_value = BeaconContentValue::LightClientOptimisticUpdate(update.into());
        gossip_beacon_content(portal_client, content_key, content_value, slot_stats).await
    }

    async fn serve_light_client_finality_update(
        api: ConsensusApi,
        portal_client: HttpClient,
        finalized_slot: Arc<Mutex<u64>>,
        slot_stats: Arc<StdMutex<BeaconSlotStats>>,
    ) -> anyhow::Result<()> {
        let data = api.get_lc_finality_update().await?;
        let update: Value = serde_json::from_str(&data)?;
        let update: LightClientFinalityUpdateDeneb =
            serde_json::from_value(update["data"].clone())?;
        info!(
            finalized_slot = %update.finalized_header.beacon.slot,
            "Generated LightClientFinalityUpdate",
        );
        let new_finalized_slot = update.finalized_header.beacon.slot;

        match new_finalized_slot.cmp(&*finalized_slot.lock().await) {
            Ordering::Equal => {
                // We already gossiped the latest finality updated with the same finalized slot, no
                // need to serve it again.
                return Ok(());
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

        gossip_beacon_content(portal_client, content_key, content_value, slot_stats).await?;
        *finalized_slot.lock().await = new_finalized_slot;

        Ok(())
    }

    async fn serve_historical_summaries_with_proof(
        api: ConsensusApi,
        portal_client: HttpClient,
        slot_stats: Arc<StdMutex<BeaconSlotStats>>,
        finalized_state_root: Arc<Mutex<FinalizedBeaconState>>,
    ) -> anyhow::Result<()> {
        if finalized_state_root.lock().await.in_progress {
            // If the beacon state download is in progress, do not serve a new historical summary.
            info!("Beacon state download is in progress, skipping HistoricalSummariesWithProof generation.");
            return Ok(());
        }

        let finalized_state_root_data = api.get_beacon_state_finalized_root().await?;
        let finalized_state_root_data: Value = serde_json::from_str(&finalized_state_root_data)?;
        let latest_finalized_state_root: String =
            serde_json::from_value(finalized_state_root_data["data"]["root"].clone())?;

        if latest_finalized_state_root.eq(&finalized_state_root.lock().await.state_root) {
            // We already gossiped the latest historical summaries from the current finalized root,
            // no need to serve it again.
            info!(
                epoch = %latest_finalized_state_root,
                "No new HistoricalSummariesWithProof to serve",
            );
            return Ok(());
        }

        // Serve the latest historical summaries from the new finalized beacon state
        info!("Downloading beacon state for HistoricalSummariesWithProof generation...");
        finalized_state_root.lock().await.in_progress = true;
        let beacon_state = api.get_beacon_state().await?;
        let beacon_state: Value = serde_json::from_str(&beacon_state)?;
        let beacon_state: BeaconStateDeneb = serde_json::from_value(beacon_state["data"].clone())?;
        let state_epoch = beacon_state.slot / SLOTS_PER_EPOCH;
        let historical_summaries_proof = beacon_state.build_historical_summaries_proof();
        // Ensure the historical summaries proof is of the correct length
        ensure!(
            historical_summaries_proof.len() == HISTORICAL_SUMMARIES_PROOF_LENGTH,
            "Historical summaries proof length is not 5"
        );
        let historical_summaries = beacon_state.historical_summaries;
        let historical_summaries_with_proof = ForkVersionedHistoricalSummariesWithProof {
            fork_name: ForkName::Deneb,
            historical_summaries_with_proof: HistoricalSummariesWithProof {
                epoch: state_epoch,
                historical_summaries,
                proof: HistoricalSummariesStateProof::from(historical_summaries_proof),
            },
        };
        info!(
            epoch = %state_epoch,
            "Generated HistoricalSummariesWithProof",
        );
        let content_key =
            BeaconContentKey::HistoricalSummariesWithProof(HistoricalSummariesWithProofKey {
                epoch: state_epoch,
            });
        let content_value =
            BeaconContentValue::HistoricalSummariesWithProof(historical_summaries_with_proof);

        gossip_beacon_content(portal_client, content_key, content_value, slot_stats).await?;
        finalized_state_root.lock().await.state_root = latest_finalized_state_root;
        finalized_state_root.lock().await.in_progress = false;

        Ok(())
    }
}
