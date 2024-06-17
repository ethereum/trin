use anyhow::anyhow;
use chrono::Duration;
use ssz::Decode;
use std::sync::Arc;

use ethportal_api::{
    consensus::fork::ForkName,
    types::content_value::beacon::{
        ForkVersionedHistoricalSummariesWithProof, ForkVersionedLightClientBootstrap,
        ForkVersionedLightClientFinalityUpdate, ForkVersionedLightClientOptimisticUpdate,
        LightClientUpdatesByRange,
    },
    BeaconContentKey,
};
use light_client::consensus::rpc::portal_rpc::expected_current_slot;
use tokio::sync::RwLock;

use trin_validation::{
    oracle::HeaderOracle,
    validator::{ValidationResult, Validator},
};

pub struct BeaconValidator {
    // TODO: HeaderOracle is not network agnostic name
    pub header_oracle: Arc<RwLock<HeaderOracle>>,
}

impl Validator<BeaconContentKey> for BeaconValidator {
    async fn validate_content(
        &self,
        content_key: &BeaconContentKey,
        content: &[u8],
    ) -> anyhow::Result<ValidationResult<BeaconContentKey>> {
        match content_key {
            BeaconContentKey::LightClientBootstrap(_) => {
                let bootstrap = ForkVersionedLightClientBootstrap::from_ssz_bytes(content)
                    .map_err(|err| {
                        anyhow!(
                            "Fork versioned light client bootstrap has invalid SSZ bytes: {:?}",
                            err
                        )
                    })?;

                // Check if the light client bootstrap slot is ole than 4 months
                let four_months = Duration::days(30 * 4);
                let four_months_in_senonds = four_months.num_seconds();
                let four_months_in_slots: u64 = (four_months_in_senonds / 12) as u64;
                let four_months_ago_slot = expected_current_slot() - four_months_in_slots;
                let bootstrap_slot = bootstrap.get_slot();

                if bootstrap_slot < four_months_ago_slot {
                    return Err(anyhow!(
                        "Light client bootstrap slot is too old: {}",
                        bootstrap_slot
                    ));
                }
            }
            BeaconContentKey::LightClientUpdatesByRange(key) => {
                let lc_updates =
                    LightClientUpdatesByRange::from_ssz_bytes(content).map_err(|err| {
                        anyhow!(
                            "Light client updates by range has invalid SSZ bytes: {:?}",
                            err
                        )
                    })?;

                // Check if lc updates count match the content key count
                if lc_updates.0.len() as u64 != key.count {
                    return Err(anyhow!(
                        "Light client updates count does not match the content key count: {} != {}",
                        lc_updates.0.len(),
                        key.count
                    ));
                }
            }
            BeaconContentKey::LightClientFinalityUpdate(key) => {
                let lc_finality_update = ForkVersionedLightClientFinalityUpdate::from_ssz_bytes(
                    content,
                )
                .map_err(|err| {
                    anyhow!(
                        "Fork versioned light client finality update has invalid SSZ bytes: {:?}",
                        err
                    )
                })?;

                // Check if the light client finality update is from the recent fork
                if lc_finality_update.fork_name != ForkName::Deneb {
                    return Err(anyhow!(
                        "Light client finality update is not from the recent fork. Expected Deneb, got {}",
                        lc_finality_update.fork_name
                    ));
                }

                // Check if key finalized slot matches the light client finality update finalized
                // slot
                let finalized_slot = lc_finality_update.get_finalized_slot();

                if key.finalized_slot != finalized_slot {
                    return Err(anyhow!(
                        "Light client finality update finalized slot does not match the content key finalized slot: {} != {}",
                        finalized_slot,
                        key.finalized_slot
                    ));
                }
            }
            BeaconContentKey::LightClientOptimisticUpdate(key) => {
                let lc_optimistic_update =
                    ForkVersionedLightClientOptimisticUpdate::from_ssz_bytes(content).map_err(
                        |err| {
                            anyhow!(
                        "Fork versioned light client optimistic update has invalid SSZ bytes: {:?}",
                        err
                    )
                        },
                    )?;

                // Check if the light client optimistic update is from the recent fork
                if lc_optimistic_update.fork_name != ForkName::Deneb {
                    return Err(anyhow!(
                        "Light client optimistic update is not from the recent fork. Expected Deneb, got {}",
                        lc_optimistic_update.fork_name
                    ));
                }

                // Check if key signature slot matches the light client optimistic update signature
                // slot
                if &key.signature_slot != lc_optimistic_update.update.signature_slot() {
                    return Err(anyhow!(
                        "Light client optimistic update signature slot does not match the content key signature slot: {} != {}",
                        lc_optimistic_update.update.signature_slot(),
                        key.signature_slot
                    ));
                }
            }
            BeaconContentKey::HistoricalSummariesWithProof(key) => {
                let fork_versioned_historical_summaries =
                    ForkVersionedHistoricalSummariesWithProof::from_ssz_bytes(content).map_err(
                        |err| {
                            anyhow!(
                                "Historical summaries with proof has invalid SSZ bytes: {:?}",
                                err
                            )
                        },
                    )?;

                // Check if the historical summaries with proof epoch matches the content key epoch
                if fork_versioned_historical_summaries
                    .historical_summaries_with_proof
                    .epoch
                    != key.epoch
                {
                    return Err(anyhow!(
                        "Historical summaries with proof epoch does not match the content key epoch: {} != {}",
                        fork_versioned_historical_summaries.historical_summaries_with_proof.epoch,
                        key.epoch
                    ));
                }

                // TODO: Validate the historical summaries with proof against current state root
            }
        }

        Ok(ValidationResult::new(true))
    }
}
