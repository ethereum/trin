use std::sync::Arc;

use alloy::primitives::B256;
use anyhow::anyhow;
use chrono::Duration;
use ethportal_api::{
    consensus::{
        fork::ForkName,
        historical_summaries::{
            HistoricalSummariesProof, HistoricalSummariesWithProof, HISTORICAL_SUMMARIES_GINDEX,
        },
    },
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
use tokio::sync::RwLock;
use tracing::warn;
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

                if key.finalized_slot > finalized_slot {
                    return Err(anyhow!(
                        "Light client finality update finalized slot should be equal or greater than content key finalized slot: {} < {}",
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
                let historical_summaries_with_proof =
                    Self::general_summaries_validation(content, key)?;

                let latest_finalized_root = self
                    .header_oracle
                    .read()
                    .await
                    .get_finalized_state_root()
                    .await;

                if let Ok(latest_finalized_root) = latest_finalized_root {
                    Self::state_summaries_validation(
                        historical_summaries_with_proof,
                        latest_finalized_root,
                    )?
                } else {
                    warn!("Failed to get latest finalized state root. Bypassing historical summaries with proof validation");
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
    ) -> anyhow::Result<HistoricalSummariesWithProof> {
        let fork_versioned_historical_summaries =
            ForkVersionedHistoricalSummariesWithProof::from_ssz_bytes(content).map_err(|err| {
                anyhow!("Historical summaries with proof has invalid SSZ bytes: {err:?}")
            })?;

        let historical_summaries_with_proof =
            fork_versioned_historical_summaries.historical_summaries_with_proof;

        // Check if the historical summaries with proof epoch matches the content key epoch
        if historical_summaries_with_proof.epoch != key.epoch {
            return Err(anyhow!(
                        "Historical summaries with proof epoch does not match the content key epoch: {} != {}",
                        historical_summaries_with_proof.epoch,
                        key.epoch
                    ));
        }
        Ok(historical_summaries_with_proof)
    }

    /// Validate historical summaries against the latest finalized state root
    fn state_summaries_validation(
        historical_summaries_with_proof: HistoricalSummariesWithProof,
        latest_finalized_root: B256,
    ) -> anyhow::Result<()> {
        if verify_merkle_proof(
            historical_summaries_with_proof
                .historical_summaries
                .tree_hash_root(),
            &historical_summaries_with_proof.proof,
            HistoricalSummariesProof::capacity(),
            HISTORICAL_SUMMARIES_GINDEX,
            latest_finalized_root,
        ) {
            Ok(())
        } else {
            Err(anyhow!(
                "Merkle proof validation failed for HistoricalSummariesProof"
            ))
        }
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use ethportal_api::{
        types::{
            content_key::beacon::{LightClientFinalityUpdateKey, LightClientOptimisticUpdateKey},
            content_value::beacon::LightClientUpdatesByRange,
            jsonrpc::{
                endpoints::BeaconEndpoint, json_rpc_mock::MockJsonRpcBuilder,
                request::JsonRpcRequest,
            },
        },
        BeaconContentValue, ContentValue, LightClientBootstrapKey, LightClientUpdatesByRangeKey,
    };
    use serde::Deserialize;
    use ssz::Encode;
    use ssz_types::VariableList;
    use tokio::sync::mpsc::UnboundedSender;
    use trin_utils::{submodules::read_yaml_portal_spec_tests_file, testing::ContentItem};

    use super::*;
    use crate::test_utils;

    #[tokio::test]
    async fn test_validate_light_client_bootstrap() {
        let validator = create_validator();
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
        bootstrap.bootstrap.header_deneb_mut().unwrap().beacon.slot = 0;
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
        let validator = create_validator();
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
        let validator = create_validator();
        let finality_update = test_utils::get_light_client_finality_update(0);
        let content = finality_update.as_ssz_bytes();
        let content_key =
            BeaconContentKey::LightClientFinalityUpdate(LightClientFinalityUpdateKey {
                finalized_slot: 10934316269310501102,
            });

        let result = validator
            .validate_content(&content_key, &content)
            .await
            .unwrap();

        assert!(result.valid_for_storing);

        // Expect error because the content key finalized slot is greaten than the light client
        // update  finalized slot
        let invalid_content_key =
            BeaconContentKey::LightClientFinalityUpdate(LightClientFinalityUpdateKey {
                finalized_slot: 10934316269310501102 + 1,
            });
        let result = validator
            .validate_content(&invalid_content_key, &content)
            .await
            .unwrap_err();

        assert_eq!(
            result.to_string(),
            "Light client finality update finalized slot should be equal or greater than content key finalized slot: 10934316269310501102 < 10934316269310501103"
        );
    }

    #[tokio::test]
    async fn test_validate_light_client_optimistic_update() {
        let validator = create_validator();
        let optimistic_update = test_utils::get_light_client_optimistic_update(0);
        let content = optimistic_update.as_ssz_bytes();
        let content_key =
            BeaconContentKey::LightClientOptimisticUpdate(LightClientOptimisticUpdateKey {
                signature_slot: 15067541596220156845,
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
            "Light client optimistic update signature slot does not match the content key signature slot: 15067541596220156845 != 0"
        );
    }

    mod historical_summaries {
        use super::*;

        #[tokio::test]
        async fn validate() {
            let test_data = read_test_data();

            let validation_result = test_data
                .create_validator()
                .validate_content(
                    &test_data.content.content_key,
                    &test_data.content.raw_content_value,
                )
                .await
                .expect("Should validate content");
            assert!(validation_result.valid_for_storing);
        }

        #[tokio::test]
        #[should_panic = "Historical summaries with proof epoch does not match the content key epoch"]
        async fn validate_invalid_epoch() {
            let test_data = read_test_data();

            // Modify content key
            let mut content_key = test_data.content.content_key.clone();
            if let BeaconContentKey::HistoricalSummariesWithProof(key) = &mut content_key {
                key.epoch += 1;
            }

            test_data
                .create_validator()
                .validate_content(&content_key, &test_data.content.raw_content_value)
                .await
                .unwrap();
        }

        #[tokio::test]
        #[should_panic = "Merkle proof validation failed for HistoricalSummariesProof"]
        async fn validate_invalid_proof() {
            let test_data = read_test_data();

            // Modify proof
            let mut content_value = test_data.content.content_value().unwrap();
            if let BeaconContentValue::HistoricalSummariesWithProof(
                fork_versioned_historical_summaries_with_proof,
            ) = &mut content_value
            {
                fork_versioned_historical_summaries_with_proof
                    .historical_summaries_with_proof
                    .proof
                    .swap(0, 1);
            }

            test_data
                .create_validator()
                .validate_content(&test_data.content.content_key, &content_value.encode())
                .await
                .unwrap();
        }

        fn read_test_data() -> TestData {
            read_yaml_portal_spec_tests_file(
            "tests/mainnet/beacon_chain/historical_summaries_with_proof/electra/historical_summaries_with_proof.yaml",
        ).unwrap()
        }

        #[derive(Deserialize)]
        struct TestData {
            #[serde(flatten)]
            content: ContentItem<BeaconContentKey>,
            beacon_state_root: B256,
        }

        impl TestData {
            fn create_validator(&self) -> BeaconValidator {
                create_validator_with_beacon_jsonrpc(
                    MockJsonRpcBuilder::new()
                        .with_response(BeaconEndpoint::FinalizedStateRoot, self.beacon_state_root)
                        .or_fail(),
                )
            }
        }
    }

    fn create_validator() -> BeaconValidator {
        BeaconValidator::new(Arc::new(RwLock::new(HeaderOracle::new())))
    }

    fn create_validator_with_beacon_jsonrpc(
        beacon_jsonrpc_tx: UnboundedSender<JsonRpcRequest<BeaconEndpoint>>,
    ) -> BeaconValidator {
        let mut header_oracle = HeaderOracle::new();
        header_oracle.beacon_jsonrpc_tx = Some(beacon_jsonrpc_tx);
        BeaconValidator::new(Arc::new(RwLock::new(header_oracle)))
    }
}
