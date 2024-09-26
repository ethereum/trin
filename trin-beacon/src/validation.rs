use alloy_primitives::B256;
use anyhow::anyhow;
use chrono::Duration;
use ethportal_api::{
    consensus::fork::ForkName,
    light_client::{
        finality_update::LightClientFinalityUpdate, optimistic_update::LightClientOptimisticUpdate,
        update::LightClientUpdate,
    },
    types::{
        content_key::beacon::HistoricalSummariesWithProofKey,
        content_value::beacon::{
            ForkVersionedHistoricalSummariesWithProof, ForkVersionedLightClientBootstrap,
            ForkVersionedLightClientFinalityUpdate, ForkVersionedLightClientOptimisticUpdate,
            LightClientUpdatesByRange,
        },
    },
    BeaconContentKey,
};
use light_client::{
    config::Network,
    consensus::{
        rpc::portal_rpc::expected_current_slot, types::GenericUpdate, verify_generic_update,
    },
};
use ssz::Decode;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;
use tree_hash::TreeHash;
use trin_validation::{
    merkle::proof::verify_merkle_proof,
    oracle::HeaderOracle,
    validator::{ValidationResult, Validator},
};

pub struct BeaconValidator {
    // TODO: HeaderOracle is not network agnostic name
    pub header_oracle: Arc<RwLock<HeaderOracle>>,
    pub genesis_root: Vec<u8>,
    pub fork_version: Vec<u8>,
}

impl BeaconValidator {
    pub fn new(header_oracle: Arc<RwLock<HeaderOracle>>) -> Self {
        let light_client_network = Network::Mainnet;
        let light_client_config = light_client_network.to_base_config();
        let genesis_root = light_client_config.chain.genesis_root;
        let fork_version = light_client_config.forks.deneb.fork_version;
        Self {
            header_oracle,
            genesis_root,
            fork_version,
        }
    }
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

                let finalized_header = self.header_oracle.read().await.get_finalized_header().await;
                let bootstrap_block_header = bootstrap.bootstrap.get_beacon_block_header();

                if let Ok(finalized_header) = finalized_header {
                    if finalized_header != bootstrap_block_header {
                        return Err(anyhow!(
                            "Light client bootstrap header does not match the finalized header: {finalized_header:?} != {bootstrap_block_header:?}",
                        ));
                    }
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

                if let Ok(light_client_store) = self
                    .header_oracle
                    .read()
                    .await
                    .get_light_client_store()
                    .await
                {
                    let expected_slot = expected_current_slot();
                    for update in lc_updates.0.iter() {
                        match &update.update {
                            LightClientUpdate::Deneb(update) => {
                                let generic_update: GenericUpdate = update.into();
                                verify_generic_update(
                                    &light_client_store,
                                    &generic_update,
                                    expected_slot,
                                    &self.genesis_root,
                                    &self.fork_version,
                                )?;
                            }
                            _ => {
                                return Err(anyhow!("Unsupported light client update fork version"))
                            }
                        }
                    }
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
                        "Light client finality update is not from the recent fork. Expected deneb, got {}",
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

                match &lc_finality_update.update {
                    LightClientFinalityUpdate::Deneb(update) => {
                        if let Ok(light_client_store) = self
                            .header_oracle
                            .read()
                            .await
                            .get_light_client_store()
                            .await
                        {
                            let generic_update: GenericUpdate = update.into();
                            verify_generic_update(
                                &light_client_store,
                                &generic_update,
                                expected_current_slot(),
                                &self.genesis_root,
                                &self.fork_version,
                            )?;
                        }
                    }
                    _ => {
                        return Err(anyhow!(
                            "Unsupported light client finality update fork version"
                        ))
                    }
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
                        "Light client optimistic update is not from the recent fork. Expected deneb, got {}",
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

                match &lc_optimistic_update.update {
                    LightClientOptimisticUpdate::Deneb(update) => {
                        if let Ok(light_client_store) = self
                            .header_oracle
                            .read()
                            .await
                            .get_light_client_store()
                            .await
                        {
                            let generic_update: GenericUpdate = update.into();

                            verify_generic_update(
                                &light_client_store,
                                &generic_update,
                                expected_current_slot(),
                                &self.genesis_root,
                                &self.fork_version,
                            )?;
                        }
                    }
                    _ => {
                        return Err(anyhow!(
                            "Unsupported light client optimistic update fork version"
                        ))
                    }
                }
            }
            BeaconContentKey::HistoricalSummariesWithProof(key) => {
                let fork_versioned_historical_summaries =
                    Self::general_summaries_validation(content, key)?;

                let latest_finalized_root = self
                    .header_oracle
                    .read()
                    .await
                    .get_finalized_state_root()
                    .await;

                if let Ok(latest_finalized_root) = latest_finalized_root {
                    Self::state_summaries_validation(
                        fork_versioned_historical_summaries,
                        latest_finalized_root,
                    )
                    .await?;
                } else {
                    debug!("Failed to get latest finalized state root. Bypassing historical summaries with proof validation");
                }
            }
        }

        Ok(ValidationResult::new(true))
    }
}

impl BeaconValidator {
    /// General validation for the historical summaries with proof content
    fn general_summaries_validation(
        content: &[u8],
        key: &HistoricalSummariesWithProofKey,
    ) -> anyhow::Result<ForkVersionedHistoricalSummariesWithProof> {
        let fork_versioned_historical_summaries =
            ForkVersionedHistoricalSummariesWithProof::from_ssz_bytes(content).map_err(|err| {
                anyhow!("Historical summaries with proof has invalid SSZ bytes: {err:?}")
            })?;

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
        Ok(fork_versioned_historical_summaries)
    }

    /// Validate historical summaries against the latest finalized state root
    async fn state_summaries_validation(
        fork_versioned_historical_summaries: ForkVersionedHistoricalSummariesWithProof,
        latest_finalized_root: B256,
    ) -> anyhow::Result<()> {
        let historical_summaries_state_proof = fork_versioned_historical_summaries
            .historical_summaries_with_proof
            .proof;
        let historical_summaries_root = fork_versioned_historical_summaries
            .historical_summaries_with_proof
            .historical_summaries
            .tree_hash_root();

        // let gen_index =
        // 31 (because there are 31 top level leafs) +
        // 28 (the position of historical_summaries field in BeaconState)
        let gen_index = 59;

        if !verify_merkle_proof(
            historical_summaries_root,
            &historical_summaries_state_proof,
            5,
            gen_index,
            latest_finalized_root,
        ) {
            return Err(anyhow!(
                "Merkle proof validation failed for HistoricalSummariesProof"
            ));
        }
        Ok(())
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::test_utils;
    use ethportal_api::{
        types::{
            content_key::beacon::{
                HistoricalSummariesWithProofKey, LightClientFinalityUpdateKey,
                LightClientOptimisticUpdateKey,
            },
            content_value::beacon::LightClientUpdatesByRange,
        },
        LightClientBootstrapKey, LightClientUpdatesByRangeKey,
    };
    use ssz::Encode;
    use ssz_types::VariableList;

    #[tokio::test]
    async fn test_validate_light_client_bootstrap() {
        let validator = BeaconValidator::new(Arc::new(RwLock::new(HeaderOracle::default())));
        let mut bootstrap = test_utils::get_light_client_bootstrap(0);
        let content = bootstrap.as_ssz_bytes();
        let content_key = BeaconContentKey::LightClientBootstrap(LightClientBootstrapKey {
            block_hash: [0; 32],
        });
        let result = validator
            .validate_content(&content_key, &content)
            .await
            .unwrap();

        assert!(result.valid_for_storing);

        // Expect error because the light client bootstrap slot is too old
        bootstrap
            .bootstrap
            .header_capella_mut()
            .unwrap()
            .beacon
            .slot = 0;
        let content = bootstrap.as_ssz_bytes();
        let result = validator
            .validate_content(&content_key, &content)
            .await
            .unwrap_err();

        assert_eq!(
            result.to_string(),
            "Light client bootstrap slot is too old: 0"
        );
    }

    #[tokio::test]
    async fn test_validate_light_client_updates_by_range() {
        let validator = BeaconValidator::new(Arc::new(RwLock::new(HeaderOracle::default())));
        let lc_update_0 = test_utils::get_light_client_update(0);
        let updates = LightClientUpdatesByRange(VariableList::from(vec![lc_update_0.clone()]));
        let content = updates.as_ssz_bytes();
        let content_key =
            BeaconContentKey::LightClientUpdatesByRange(LightClientUpdatesByRangeKey {
                start_period: 0,
                count: 1,
            });
        let result = validator
            .validate_content(&content_key, &content)
            .await
            .unwrap();

        assert!(result.valid_for_storing);

        let lc_update_1 = test_utils::get_light_client_update(1);
        let updates = LightClientUpdatesByRange(VariableList::from(vec![lc_update_0, lc_update_1]));
        let content = updates.as_ssz_bytes();
        // Expect error because the count does not match the content key count
        let result = validator
            .validate_content(&content_key, &content)
            .await
            .unwrap_err();

        assert_eq!(
            result.to_string(),
            "Light client updates count does not match the content key count: 2 != 1"
        );
    }

    #[tokio::test]
    async fn test_validate_light_client_finality_update() {
        let validator = BeaconValidator::new(Arc::new(RwLock::new(HeaderOracle::default())));
        let mut finality_update = test_utils::get_light_client_finality_update(0);
        let content = finality_update.as_ssz_bytes();
        let content_key =
            BeaconContentKey::LightClientFinalityUpdate(LightClientFinalityUpdateKey {
                finalized_slot: 17748599031001599584,
            });

        let result = validator
            .validate_content(&content_key, &content)
            .await
            .unwrap();

        assert!(result.valid_for_storing);

        // Expect error because the finalized slot does not match the content key finalized slot
        let invalid_content_key =
            BeaconContentKey::LightClientFinalityUpdate(LightClientFinalityUpdateKey {
                finalized_slot: 0,
            });
        let result = validator
            .validate_content(&invalid_content_key, &content)
            .await
            .unwrap_err();

        assert_eq!(
            result.to_string(),
            "Light client finality update finalized slot does not match the content key finalized slot: 17748599031001599584 != 0"
        );

        // Expect error because the light client finality update is not from the recent fork
        finality_update.fork_name = ForkName::Capella;
        let content = finality_update.as_ssz_bytes();
        let result = validator
            .validate_content(&content_key, &content)
            .await
            .unwrap_err();

        assert_eq!(
            result.to_string(),
            "Light client finality update is not from the recent fork. Expected deneb, got capella"
        );
    }

    #[tokio::test]
    async fn test_validate_light_client_optimistic_update() {
        let validator = BeaconValidator::new(Arc::new(RwLock::new(HeaderOracle::default())));
        let mut optimistic_update = test_utils::get_light_client_optimistic_update(0);
        let content = optimistic_update.as_ssz_bytes();
        let content_key =
            BeaconContentKey::LightClientOptimisticUpdate(LightClientOptimisticUpdateKey {
                signature_slot: 6292665015452153680,
            });
        let result = validator
            .validate_content(&content_key, &content)
            .await
            .unwrap();

        assert!(result.valid_for_storing);

        // Expect error because the signature slot does not match the content key signature slot
        let invalid_content_key =
            BeaconContentKey::LightClientOptimisticUpdate(LightClientOptimisticUpdateKey {
                signature_slot: 0,
            });
        let result = validator
            .validate_content(&invalid_content_key, &content)
            .await
            .unwrap_err();

        assert_eq!(
            result.to_string(),
            "Light client optimistic update signature slot does not match the content key signature slot: 6292665015452153680 != 0"
        );

        // Expect error because the light client optimistic update is not from the recent fork
        optimistic_update.fork_name = ForkName::Capella;
        let content = optimistic_update.as_ssz_bytes();
        let result = validator
            .validate_content(&content_key, &content)
            .await
            .unwrap_err();

        assert_eq!(
            result.to_string(),
            "Light client optimistic update is not from the recent fork. Expected deneb, got capella"
        );
    }

    #[tokio::test]
    async fn test_validate_historical_summaries_with_proof() {
        let (summaries_with_proof, state_root) = test_utils::get_history_summaries_with_proof();
        let content = summaries_with_proof.as_ssz_bytes();
        let content_key = HistoricalSummariesWithProofKey {
            epoch: 450508969718611630,
        };
        let result = BeaconValidator::general_summaries_validation(&content, &content_key);
        assert!(result.is_ok());

        // Expect error because the epoch does not match the content key epoch
        let invalid_content_key = HistoricalSummariesWithProofKey { epoch: 0 };
        let result = BeaconValidator::general_summaries_validation(&content, &invalid_content_key)
            .unwrap_err();
        assert_eq!(
            result.to_string(),
            "Historical summaries with proof epoch does not match the content key epoch: 450508969718611630 != 0"
        );

        // Test historical summaries validation against the latest finalized state root
        let result =
            BeaconValidator::state_summaries_validation(summaries_with_proof.clone(), state_root)
                .await;
        assert!(result.is_ok());

        // Test historical summaries validation against invalid finalized state root
        let invalid_state_root = B256::random();
        let result =
            BeaconValidator::state_summaries_validation(summaries_with_proof, invalid_state_root)
                .await
                .unwrap_err();
        assert_eq!(
            result.to_string(),
            "Merkle proof validation failed for HistoricalSummariesProof"
        );
    }
}
