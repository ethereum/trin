use std::{
    cmp::Ordering,
    path::PathBuf,
    sync::{Arc, Mutex as StdMutex},
    time::{Instant, SystemTime},
};

use anyhow::{bail, ensure};
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
        network::Subnetwork,
        portal_wire::OfferTrace,
    },
    utils::bytes::hex_decode,
    BeaconContentKey, BeaconContentValue, BeaconNetworkApiClient, ContentValue,
    LightClientBootstrapKey, LightClientUpdatesByRangeKey, OverlayContentKey,
};
use jsonrpsee::http_client::HttpClient;
use serde_json::Value;
use ssz_types::VariableList;
use tokio::{
    sync::Mutex,
    time::{interval, sleep, timeout, Duration, MissedTickBehavior},
};
use tracing::{error, info, warn, Instrument};
use trin_metrics::bridge::BridgeMetricsReporter;

use super::{
    constants::SERVE_BLOCK_TIMEOUT,
    offer_report::{GlobalOfferReport, OfferReport},
};
use crate::{
    api::consensus::ConsensusApi,
    census::Census,
    constants::BEACON_GENESIS_TIME,
    types::mode::BridgeMode,
    utils::{
        duration_until_next_update, expected_current_slot, read_test_assets_from_file, TestAssets,
    },
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

/// A helper struct to hold the finalized block root and whether the `LightClientBootstrap`
/// generation is in progress.
#[derive(Clone, Debug, Default)]
pub struct FinalizedBootstrap {
    pub finalized_block_root: String,
    pub in_progress: bool,
}

impl FinalizedBootstrap {
    pub fn new() -> Self {
        Self::default()
    }
}

pub struct BeaconBridge {
    consensus_api: ConsensusApi,
    mode: BridgeMode,
    portal_client: HttpClient,
    metrics: BridgeMetricsReporter,
    /// Used to request all interested enrs in the network.
    census: Census,
    /// Global offer report for tallying total performance of beacon bridge
    global_offer_report: Arc<StdMutex<GlobalOfferReport>>,
}

impl BeaconBridge {
    pub fn new(
        consensus_api: ConsensusApi,
        mode: BridgeMode,
        portal_client: HttpClient,
        census: Census,
    ) -> Self {
        let metrics = BridgeMetricsReporter::new("beacon".to_string(), &format!("{mode:?}"));
        let global_offer_report = Arc::new(StdMutex::new(GlobalOfferReport::default()));
        Self {
            consensus_api,
            mode,
            portal_client,
            metrics,
            global_offer_report,
            census,
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
        for asset in assets.0.into_iter() {
            Self::spawn_offer_tasks(
                self.portal_client.clone(),
                asset.content_key.clone(),
                asset.content_value().expect("Error getting content value"),
                self.metrics.clone(),
                self.census.clone(),
                self.global_offer_report.clone(),
            )
            .await;
        }
    }

    ///  Get and serve the latest beacon data.
    async fn launch_latest(&self) {
        let current_period = Arc::new(Mutex::new(0));
        let finalized_bootstrap = Arc::new(Mutex::new(FinalizedBootstrap::new()));
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

            self.serve_latest(
                current_period.clone(),
                finalized_bootstrap.clone(),
                finalized_slot.clone(),
                finalized_state_root.clone(),
                self.census.clone(),
                self.global_offer_report.clone(),
            )
            .await;
        }
    }

    /// Serve latest beacon network data to the network
    ///
    /// Returns the new current period and finalized block root
    async fn serve_latest(
        &self,
        current_period: Arc<Mutex<u64>>,
        finalized_bootstrap: Arc<Mutex<FinalizedBootstrap>>,
        finalized_slot: Arc<Mutex<u64>>,
        _finalized_state_root: Arc<Mutex<FinalizedBeaconState>>,
        census: Census,
        global_offer_report: Arc<StdMutex<GlobalOfferReport>>,
    ) {
        // Serve LightClientBootstrap data
        let consensus_api_clone = self.consensus_api.clone();

        let metrics_clone = self.metrics.clone();
        let portal_client_clone = self.portal_client.clone();
        let census_clone = census.clone();
        let global_offer_report_clone = global_offer_report.clone();

        tokio::spawn(async move {
            if let Err(err) = Self::serve_light_client_bootstrap(
                consensus_api_clone,
                portal_client_clone,
                finalized_bootstrap.clone(),
                metrics_clone,
                census_clone,
                global_offer_report_clone,
            )
            .in_current_span()
            .await
            {
                finalized_bootstrap.lock().await.in_progress = false;
                warn!("Failed to serve LightClientBootstrap: {err}");
            }
        });

        // Serve `LightClientUpdate` data
        let consensus_api_clone = self.consensus_api.clone();
        let metrics_clone = self.metrics.clone();
        let portal_client_clone = self.portal_client.clone();
        let census_clone = census.clone();
        let global_offer_report_clone = global_offer_report.clone();
        tokio::spawn(async move {
            if let Err(err) = Self::serve_light_client_update(
                consensus_api_clone,
                portal_client_clone,
                current_period,
                metrics_clone,
                census_clone,
                global_offer_report_clone,
            )
            .in_current_span()
            .await
            {
                warn!("Failed to serve LightClientUpdate: {err}");
            }
        });

        // Serve `LightClientFinalityUpdate` data
        let consensus_api_clone = self.consensus_api.clone();
        let metrics_clone = self.metrics.clone();
        let portal_client_clone = self.portal_client.clone();
        let census_clone = census.clone();
        let global_offer_report_clone = global_offer_report.clone();
        tokio::spawn(async move {
            if let Err(err) = Self::serve_light_client_finality_update(
                consensus_api_clone,
                portal_client_clone,
                finalized_slot,
                metrics_clone,
                census_clone,
                global_offer_report_clone,
            )
            .in_current_span()
            .await
            {
                warn!("Failed to serve LightClientFinalityUpdate: {err}");
            }
        });

        // Serve `LightClientOptimisticUpdate` data
        let consensus_api_clone = self.consensus_api.clone();
        let metrics_clone = self.metrics.clone();
        let portal_client_clone = self.portal_client.clone();
        let census = census.clone();
        let global_offer_report_clone = global_offer_report.clone();
        tokio::spawn(async move {
            if let Err(err) = Self::serve_light_client_optimistic_update(
                consensus_api_clone,
                portal_client_clone,
                metrics_clone,
                census,
                global_offer_report_clone,
            )
            .in_current_span()
            .await
            {
                warn!("Failed to serve LightClientOptimisticUpdate: {err}");
            }
        });

        self.global_offer_report
            .lock()
            .expect("Failed to get global offer report lock")
            .report();
    }

    /// Serve `LightClientBootstrap` data
    async fn serve_light_client_bootstrap(
        consensus_api: ConsensusApi,
        portal_client: HttpClient,
        finalized_bootstrap: Arc<Mutex<FinalizedBootstrap>>,
        metrics: BridgeMetricsReporter,
        census: Census,
        global_offer_report: Arc<StdMutex<GlobalOfferReport>>,
    ) -> anyhow::Result<()> {
        if finalized_bootstrap.lock().await.in_progress {
            // If the `LightClientBootstrap` generation is in progress, do not serve a new
            // bootstrap.
            info!("LightClientBootstrap generation is in progress, skipping generation.");
            return Ok(());
        }
        let response = consensus_api
            .get_beacon_block_root("finalized".to_owned())
            .await?;
        let response: Value = serde_json::from_str(&response)?;
        let latest_finalized_block_root: String =
            serde_json::from_value(response["data"]["root"].clone())?;

        // If the latest finalized block root is the same, do not serve a new bootstrap
        if latest_finalized_block_root.eq(&*finalized_bootstrap.lock().await.finalized_block_root) {
            return Ok(());
        }

        // finalized block root is different, so serve a new bootstrap
        finalized_bootstrap.lock().await.in_progress = true;
        // Delay bootstrap generation for 2 slots (24 seconds) to ensure LightClientFinalityUpdate
        // is propagated first.
        let duration = Duration::from_secs(24);
        sleep(duration).await;
        let result = consensus_api
            .get_lc_bootstrap(&latest_finalized_block_root)
            .await?;
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
        Self::spawn_offer_tasks(
            portal_client,
            content_key,
            content_value,
            metrics,
            census,
            global_offer_report,
        )
        .await;
        finalized_bootstrap.lock().await.finalized_block_root = latest_finalized_block_root;
        finalized_bootstrap.lock().await.in_progress = false;

        Ok(())
    }

    async fn serve_light_client_update(
        consensus_api: ConsensusApi,
        portal_client: HttpClient,
        current_period: Arc<Mutex<u64>>,
        metrics: BridgeMetricsReporter,
        census: Census,
        global_offer_report: Arc<StdMutex<GlobalOfferReport>>,
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

        let data = consensus_api
            .get_lc_updates(expected_current_period, 1)
            .await?;
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
        Self::spawn_offer_tasks(
            portal_client,
            content_key,
            content_value,
            metrics,
            census,
            global_offer_report,
        )
        .await;
        *current_period.lock().await = expected_current_period;

        Ok(())
    }

    async fn serve_light_client_optimistic_update(
        consensus_api: ConsensusApi,
        portal_client: HttpClient,
        metrics: BridgeMetricsReporter,
        census: Census,
        global_offer_report: Arc<StdMutex<GlobalOfferReport>>,
    ) -> anyhow::Result<()> {
        let data = consensus_api.get_lc_optimistic_update().await?;
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
        Self::spawn_offer_tasks(
            portal_client,
            content_key,
            content_value,
            metrics,
            census,
            global_offer_report,
        )
        .await;
        Ok(())
    }

    async fn serve_light_client_finality_update(
        consensus_api: ConsensusApi,
        portal_client: HttpClient,
        finalized_slot: Arc<Mutex<u64>>,
        metrics: BridgeMetricsReporter,
        census: Census,
        global_offer_report: Arc<StdMutex<GlobalOfferReport>>,
    ) -> anyhow::Result<()> {
        let data = consensus_api.get_lc_finality_update().await?;
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

        Self::spawn_offer_tasks(
            portal_client,
            content_key,
            content_value,
            metrics,
            census,
            global_offer_report,
        )
        .await;
        *finalized_slot.lock().await = new_finalized_slot;

        Ok(())
    }

    #[allow(dead_code)] // TODO: Remove this once the method is used
    async fn serve_historical_summaries_with_proof(
        consensus_api: ConsensusApi,
        portal_client: HttpClient,
        metrics: BridgeMetricsReporter,
        finalized_state_root: Arc<Mutex<FinalizedBeaconState>>,
        census: Census,
        global_offer_report: Arc<StdMutex<GlobalOfferReport>>,
    ) -> anyhow::Result<()> {
        if finalized_state_root.lock().await.in_progress {
            // If the beacon state download is in progress, do not serve a new historical summary.
            info!("Beacon state download is in progress, skipping HistoricalSummariesWithProof generation.");
            return Ok(());
        }

        let finalized_state_root_data = consensus_api.get_beacon_state_finalized_root().await?;
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
        let beacon_state = consensus_api.get_beacon_state().await?;
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

        Self::spawn_offer_tasks(
            portal_client,
            content_key,
            content_value,
            metrics,
            census,
            global_offer_report,
        )
        .await;
        finalized_state_root.lock().await.state_root = latest_finalized_state_root;
        finalized_state_root.lock().await.in_progress = false;

        Ok(())
    }

    // spawn individual offer tasks of the content key for each interested enr found in Census
    async fn spawn_offer_tasks(
        portal_client: HttpClient,
        content_key: BeaconContentKey,
        content_value: BeaconContentValue,
        metrics: BridgeMetricsReporter,
        census: Census,
        global_offer_report: Arc<StdMutex<GlobalOfferReport>>,
    ) {
        let Ok(enrs) = census.select_peers(Subnetwork::Beacon, &content_key.content_id()) else {
            error!("Failed to request enrs for content key, skipping offer: {content_key:?}");
            return;
        };
        let offer_report = Arc::new(StdMutex::new(OfferReport::new(
            content_key.clone(),
            enrs.len(),
        )));
        let encoded_content_value = content_value.encode();
        for enr in enrs.clone() {
            let census = census.clone();
            let portal_client = portal_client.clone();
            let content_key = content_key.clone();
            let encoded_content_value = encoded_content_value.clone();
            let offer_report = offer_report.clone();
            let metrics = metrics.clone();
            let global_offer_report = global_offer_report.clone();
            tokio::spawn(async move {
                let timer = metrics.start_process_timer("spawn_offer_beacon");

                let start_time = Instant::now();
                let content_value_size = encoded_content_value.len();

                let result = timeout(
                    SERVE_BLOCK_TIMEOUT,
                    BeaconNetworkApiClient::trace_offer(
                        &portal_client,
                        enr.clone(),
                        content_key.clone(),
                        encoded_content_value,
                    ),
                )
                .await;

                let offer_trace = match &result {
                    Ok(Ok(result)) => {
                        if matches!(result, &OfferTrace::Failed) {
                            warn!("Internal error offering to: {enr}");
                        }
                        result
                    }
                    Ok(Err(err)) => {
                        warn!("Error offering to: {enr}, error: {err:?}");
                        &OfferTrace::Failed
                    }
                    Err(_) => {
                        error!("trace_offer timed out on beacon {content_key}: indicating a bug is present");
                        &OfferTrace::Failed
                    }
                };

                census.record_offer_result(
                    Subnetwork::Beacon,
                    enr.node_id(),
                    content_value_size,
                    start_time.elapsed(),
                    offer_trace,
                );

                // Update report and metrics
                global_offer_report
                    .lock()
                    .expect("to acquire lock")
                    .update(offer_trace);
                offer_report
                    .lock()
                    .expect("to acquire lock")
                    .update(&enr, offer_trace);

                metrics.report_offer(
                    match content_key {
                        BeaconContentKey::LightClientBootstrap(_) => "light_client_bootstrap",
                        BeaconContentKey::LightClientUpdatesByRange(_) => {
                            "light_client_updates_by_range"
                        }
                        BeaconContentKey::LightClientFinalityUpdate(_) => {
                            "light_client_finality_update"
                        }
                        BeaconContentKey::LightClientOptimisticUpdate(_) => {
                            "light_client_optimistic_update"
                        }
                        BeaconContentKey::HistoricalSummariesWithProof(_) => {
                            "historical_summaries_with_proof"
                        }
                    },
                    match offer_trace {
                        OfferTrace::Success(_) => "success",
                        OfferTrace::Declined => "declined",
                        OfferTrace::Failed => "failed",
                    },
                );
                metrics.stop_process_timer(timer);
            });
        }
    }
}
