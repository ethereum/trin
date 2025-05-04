use std::{
    cmp::Ordering,
    sync::{Arc, Mutex as StdMutex},
    time::{Instant, SystemTime},
};

use alloy::primitives::B256;
use anyhow::bail;
use ethportal_api::{
    consensus::{
        beacon_state::BeaconState,
        historical_summaries::{
            HistoricalSummariesWithProof, HistoricalSummariesWithProofDeneb,
            HistoricalSummariesWithProofElectra,
        },
    },
    types::{
        content_key::beacon::{
            HistoricalSummariesWithProofKey, LightClientFinalityUpdateKey,
            LightClientOptimisticUpdateKey,
        },
        content_value::beacon::LightClientUpdatesByRange,
        network::Subnetwork,
        portal_wire::OfferTrace,
    },
    BeaconContentKey, BeaconContentValue, ContentValue, LightClientBootstrapKey,
    LightClientUpdatesByRangeKey, OverlayContentKey,
};
use ssz_types::VariableList;
use tokio::{
    sync::Mutex,
    time::{interval, sleep, timeout, Duration, MissedTickBehavior},
};
use tracing::{error, info, warn, Instrument};
use trin_beacon::network::BeaconNetwork;
use trin_metrics::bridge::BridgeMetricsReporter;
use trin_validation::constants::SLOTS_PER_EPOCH;

use super::{constants::SERVE_BLOCK_TIMEOUT, offer_report::OfferReport};
use crate::{
    api::consensus::ConsensusApi,
    census::Census,
    constants::BEACON_GENESIS_TIME,
    types::mode::BridgeMode,
    utils::{duration_until_next_update, expected_current_slot},
};

/// The number of slots in a sync committee period.
const SLOTS_PER_PERIOD: u64 = SLOTS_PER_EPOCH * 256;

/// A helper struct to hold the finalized beacon state metadata.
#[derive(Clone, Debug, Default)]
pub struct FinalizedBeaconState {
    /// THe root of the finalized state
    pub state_root: B256,
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
    pub finalized_block_root: B256,
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
    beacon_network: Arc<BeaconNetwork>,
    metrics: BridgeMetricsReporter,
    /// Used to request all interested enrs in the network.
    census: Census,
}

impl BeaconBridge {
    pub fn new(
        consensus_api: ConsensusApi,
        mode: BridgeMode,
        beacon_network: Arc<BeaconNetwork>,
        census: Census,
    ) -> Self {
        let metrics = BridgeMetricsReporter::new("beacon".to_string(), &format!("{mode:?}"));
        Self {
            consensus_api,
            mode,
            beacon_network,
            metrics,
            census,
        }
    }

    pub async fn launch(&self) {
        info!("Launching beacon bridge mode: {:?}", self.mode);

        match self.mode.clone() {
            BridgeMode::Latest => self.launch_latest().await,
            other => panic!("Beacon bridge mode {other:?} not implemented!"),
        }

        info!("Bridge mode: {:?} complete.", self.mode);
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
            );
        }
    }

    /// Serve latest beacon network data to the network
    fn serve_latest(
        &self,
        current_period: Arc<Mutex<u64>>,
        finalized_bootstrap: Arc<Mutex<FinalizedBootstrap>>,
        finalized_slot: Arc<Mutex<u64>>,
        finalized_state_root: Arc<Mutex<FinalizedBeaconState>>,
    ) {
        // Serve LightClientBootstrap data
        let consensus_api_clone = self.consensus_api.clone();

        let metrics_clone = self.metrics.clone();
        let beacon_network_clone = self.beacon_network.clone();
        let census_clone = self.census.clone();

        tokio::spawn(async move {
            if let Err(err) = Self::serve_light_client_bootstrap(
                consensus_api_clone,
                beacon_network_clone,
                finalized_bootstrap.clone(),
                metrics_clone,
                census_clone,
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
        let beacon_network_clone = self.beacon_network.clone();
        let census_clone = self.census.clone();
        tokio::spawn(async move {
            if let Err(err) = Self::serve_light_client_update(
                consensus_api_clone,
                beacon_network_clone,
                current_period,
                metrics_clone,
                census_clone,
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
        let beacon_network_clone = self.beacon_network.clone();
        let census_clone = self.census.clone();
        tokio::spawn(async move {
            if let Err(err) = Self::serve_light_client_finality_update(
                consensus_api_clone,
                beacon_network_clone,
                finalized_slot,
                metrics_clone,
                census_clone,
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
        let beacon_network_clone = self.beacon_network.clone();
        let census_clone = self.census.clone();
        tokio::spawn(async move {
            if let Err(err) = Self::serve_light_client_optimistic_update(
                consensus_api_clone,
                beacon_network_clone,
                metrics_clone,
                census_clone,
            )
            .in_current_span()
            .await
            {
                warn!("Failed to serve LightClientOptimisticUpdate: {err}");
            }
        });

        // Serve `HistoricalSummariesWithProof` data
        let consensus_api_clone = self.consensus_api.clone();
        let metrics_clone = self.metrics.clone();
        let beacon_network_clone = self.beacon_network.clone();
        let census_clone = self.census.clone();
        let finalized_state_root_clone = finalized_state_root.clone();
        tokio::spawn(async move {
            if let Err(err) = Self::serve_historical_summaries_with_proof(
                consensus_api_clone,
                beacon_network_clone,
                metrics_clone,
                census_clone,
                finalized_state_root_clone,
            )
            .in_current_span()
            .await
            {
                warn!("Failed to serve HistoricalSummariesWithProof: {err}");
            }
        });
    }

    /// Serve `LightClientBootstrap` data
    async fn serve_light_client_bootstrap(
        consensus_api: ConsensusApi,
        beacon_network: Arc<BeaconNetwork>,
        finalized_bootstrap: Arc<Mutex<FinalizedBootstrap>>,
        metrics: BridgeMetricsReporter,
        census: Census,
    ) -> anyhow::Result<()> {
        if finalized_bootstrap.lock().await.in_progress {
            // If the `LightClientBootstrap` generation is in progress, do not serve a new
            // bootstrap.
            info!("LightClientBootstrap generation is in progress, skipping generation.");
            return Ok(());
        }
        let latest_finalized_block_root = consensus_api
            .get_beacon_block_root("finalized".to_owned())
            .await?
            .root;

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
        let bootstrap = consensus_api
            .get_light_client_bootstrap(latest_finalized_block_root)
            .await?;

        info!(
            header_slot=%bootstrap.get_beacon_block_header().slot,
            "Generated LightClientBootstrap",
        );

        let content_value = BeaconContentValue::LightClientBootstrap(bootstrap.into());
        let content_key = BeaconContentKey::LightClientBootstrap(LightClientBootstrapKey {
            block_hash: latest_finalized_block_root.0,
        });

        // Return the latest finalized block root if we successfully gossiped the latest bootstrap.
        Self::spawn_offer_tasks(beacon_network, content_key, content_value, metrics, census);
        finalized_bootstrap.lock().await.finalized_block_root = latest_finalized_block_root;
        finalized_bootstrap.lock().await.in_progress = false;

        Ok(())
    }

    async fn serve_light_client_update(
        consensus_api: ConsensusApi,
        beacon_network: Arc<BeaconNetwork>,
        current_period: Arc<Mutex<u64>>,
        metrics: BridgeMetricsReporter,
        census: Census,
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

        let update = consensus_api
            .get_light_client_updates(expected_current_period, 1)
            .await?
            .remove(0);
        let finalized_header_period =
            update.finalized_beacon_block_header().slot / SLOTS_PER_PERIOD;

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

        let fork_versioned_update = update.into();

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
        Self::spawn_offer_tasks(beacon_network, content_key, content_value, metrics, census);
        *current_period.lock().await = expected_current_period;

        Ok(())
    }

    async fn serve_light_client_optimistic_update(
        consensus_api: ConsensusApi,
        beacon_network: Arc<BeaconNetwork>,
        metrics: BridgeMetricsReporter,
        census: Census,
    ) -> anyhow::Result<()> {
        let update = consensus_api.get_light_client_optimistic_update().await?;
        info!(
            signature_slot = %update.signature_slot(),
            "Generated LightClientOptimisticUpdate",
        );
        let content_key = BeaconContentKey::LightClientOptimisticUpdate(
            LightClientOptimisticUpdateKey::new(*update.signature_slot()),
        );
        let content_value = BeaconContentValue::LightClientOptimisticUpdate(update.into());
        Self::spawn_offer_tasks(beacon_network, content_key, content_value, metrics, census);
        Ok(())
    }

    async fn serve_light_client_finality_update(
        consensus_api: ConsensusApi,
        beacon_network: Arc<BeaconNetwork>,
        finalized_slot: Arc<Mutex<u64>>,
        metrics: BridgeMetricsReporter,
        census: Census,
    ) -> anyhow::Result<()> {
        let update = consensus_api.get_light_client_finality_update().await?;
        let new_finalized_slot = update.finalized_beacon_block_header().slot;
        info!(
            finalized_slot = new_finalized_slot,
            "Generated LightClientFinalityUpdate",
        );

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

        Self::spawn_offer_tasks(beacon_network, content_key, content_value, metrics, census);
        *finalized_slot.lock().await = new_finalized_slot;

        Ok(())
    }

    async fn serve_historical_summaries_with_proof(
        consensus_api: ConsensusApi,
        beacon_network: Arc<BeaconNetwork>,
        metrics: BridgeMetricsReporter,
        census: Census,
        finalized_state_root: Arc<Mutex<FinalizedBeaconState>>,
    ) -> anyhow::Result<()> {
        if finalized_state_root.lock().await.in_progress {
            // If the beacon state download is in progress, do not serve a new historical summary.
            info!("Beacon state download is in progress, skipping HistoricalSummariesWithProof generation.");
            return Ok(());
        }

        let latest_finalized_state_root =
            consensus_api.get_beacon_state_finalized_root().await?.root;

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
        let state_epoch = beacon_state.slot() / SLOTS_PER_EPOCH;
        let historical_summaries_with_proof = match beacon_state {
            BeaconState::Bellatrix(_) => {
                bail!("Unexpected Bellatrix BeaconState while serving historical summaries")
            }
            BeaconState::Capella(_) => {
                bail!("Unexpected Capella BeaconState while serving historical summaries")
            }
            BeaconState::Deneb(beacon_state) => {
                let historical_summaries_proof = beacon_state.build_historical_summaries_proof();
                HistoricalSummariesWithProof::Deneb(HistoricalSummariesWithProofDeneb {
                    epoch: state_epoch,
                    historical_summaries: beacon_state.historical_summaries,
                    proof: historical_summaries_proof,
                })
            }
            BeaconState::Electra(beacon_state) => {
                let historical_summaries_proof = beacon_state.build_historical_summaries_proof();
                HistoricalSummariesWithProof::Electra(HistoricalSummariesWithProofElectra {
                    epoch: state_epoch,
                    historical_summaries: beacon_state.historical_summaries,
                    proof: historical_summaries_proof,
                })
            }
        };
        info!(
            epoch = %state_epoch,
            "Generated HistoricalSummariesWithProof",
        );
        let content_key =
            BeaconContentKey::HistoricalSummariesWithProof(HistoricalSummariesWithProofKey {
                epoch: state_epoch,
            });
        let content_value = BeaconContentValue::HistoricalSummariesWithProof(
            historical_summaries_with_proof.into(),
        );

        Self::spawn_offer_tasks(beacon_network, content_key, content_value, metrics, census);
        finalized_state_root.lock().await.state_root = latest_finalized_state_root;
        finalized_state_root.lock().await.in_progress = false;

        Ok(())
    }

    // spawn individual offer tasks of the content key for each interested enr found in Census
    fn spawn_offer_tasks(
        beacon_network: Arc<BeaconNetwork>,
        content_key: BeaconContentKey,
        content_value: BeaconContentValue,
        metrics: BridgeMetricsReporter,
        census: Census,
    ) {
        let Ok(peers) = census.select_peers(Subnetwork::Beacon, &content_key.content_id()) else {
            error!("Failed to request enrs for content key, skipping offer: {content_key:?}");
            return;
        };
        let offer_report = Arc::new(StdMutex::new(OfferReport::new(
            content_key.clone(),
            peers.len(),
        )));
        let encoded_content_value = content_value.encode();
        for peer in peers.clone() {
            let census = census.clone();
            let beacon_network = beacon_network.clone();
            let content_key = content_key.clone();
            let encoded_content_value = encoded_content_value.clone();
            let offer_report = offer_report.clone();
            let metrics = metrics.clone();
            tokio::spawn(async move {
                let timer = metrics.start_process_timer("spawn_offer_beacon");

                let start_time = Instant::now();
                let content_value_size = encoded_content_value.len();

                let result = timeout(
                    SERVE_BLOCK_TIMEOUT,
                    beacon_network.overlay.send_offer_trace(
                        peer.enr.clone(),
                        content_key.to_bytes(),
                        encoded_content_value,
                    ),
                )
                .await;

                let offer_trace = match &result {
                    Ok(Ok(result)) => {
                        if matches!(result, &OfferTrace::Failed) {
                            warn!("Internal error offering to: {}", peer.enr);
                        }
                        result
                    }
                    Ok(Err(err)) => {
                        warn!("Error offering to: {}, error: {err:?}", peer.enr);
                        &OfferTrace::Failed
                    }
                    Err(_) => {
                        error!("trace_offer timed out on beacon {content_key}: indicating a bug is present");
                        &OfferTrace::Failed
                    }
                };

                census.record_offer_result(
                    Subnetwork::Beacon,
                    peer.enr.node_id(),
                    content_value_size,
                    start_time.elapsed(),
                    offer_trace,
                );

                // Update report and metrics
                offer_report
                    .lock()
                    .expect("to acquire lock")
                    .update(&peer, offer_trace);

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
                    &peer.client_type,
                    offer_trace,
                );
                metrics.stop_process_timer(timer);
            });
        }
    }
}
