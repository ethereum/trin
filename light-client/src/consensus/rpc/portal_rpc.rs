use crate::consensus::rpc::ConsensusRpc;
use async_trait::async_trait;
use ethportal_api::consensus::light_client::bootstrap::LightClientBootstrap;
use ethportal_api::light_client::bootstrap::LightClientBootstrapCapella;
use ethportal_api::light_client::finality_update::LightClientFinalityUpdateCapella;
use ethportal_api::light_client::optimistic_update::LightClientOptimisticUpdateCapella;
use ethportal_api::light_client::update::LightClientUpdateCapella;
use ethportal_api::types::consensus::light_client::finality_update::LightClientFinalityUpdate;
use ethportal_api::types::consensus::light_client::optimistic_update::LightClientOptimisticUpdate;
use ethportal_api::types::consensus::light_client::update::LightClientUpdate;
use ethportal_api::types::content_key::beacon::LightClientFinalityUpdateKey;
use ethportal_api::types::content_key::beacon::LightClientOptimisticUpdateKey;
use ethportal_api::{
    BeaconContentKey, BeaconContentValue, ContentValue, LightClientBootstrapKey,
    LightClientUpdatesByRangeKey,
};
use eyre::eyre;
use futures::channel::oneshot;
use portalnet::overlay_service::OverlayCommand;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::UnboundedSender;
use tracing::warn;
pub const BEACON_GENESIS_TIME: u64 = 1606824023;

#[derive(Clone, Debug)]
pub struct PortalRpc {
    overlay_tx: UnboundedSender<OverlayCommand<BeaconContentKey>>,
}

impl PortalRpc {
    pub fn with_portal(overlay_tx: UnboundedSender<OverlayCommand<BeaconContentKey>>) -> Self {
        Self { overlay_tx }
    }
}

#[async_trait]
impl ConsensusRpc for PortalRpc {
    fn new(_path: &str) -> Self {
        unreachable!("PortalRpc does not use path.")
    }

    async fn get_bootstrap(
        &self,
        block_root: &'_ [u8],
    ) -> eyre::Result<LightClientBootstrapCapella> {
        let bootstrap_key = BeaconContentKey::LightClientBootstrap(LightClientBootstrapKey {
            block_hash: <[u8; 32]>::try_from(block_root)?,
        });

        let (tx, rx) = oneshot::channel();

        let overlay_command = OverlayCommand::FindContentQuery {
            target: bootstrap_key,
            callback: tx,
            is_trace: false,
        };

        if let Err(err) = self.overlay_tx.send(overlay_command) {
            warn!(
                protocol = "beacon",
                error = %err,
                "Error submitting FindContent query to service"
            );
            return Err(err.into());
        }

        match rx.await {
            Ok(result) => {
                let bootstrap = BeaconContentValue::decode(
                    &result
                        .0
                        .ok_or("LightClientBootstrap content not found on the network.")
                        .map_err(|err| eyre!("{err}"))?,
                )?;

                if let BeaconContentValue::LightClientBootstrap(bootstrap) = bootstrap {
                    if let LightClientBootstrap::Capella(bootstrap_capella) = bootstrap.bootstrap {
                        Ok(bootstrap_capella)
                    } else {
                        return Err(eyre!(
                            "Error converting LightClientBootstrap to LightClientBootstrapCapella"
                        ));
                    }
                } else {
                    return Err(eyre!(
                        "Error converting BeaconContentValue to LightClientBootstrap"
                    ));
                }
            }
            Err(err) => {
                warn!(
                    protocol = %"beacon",
                    error = %err,
                    "Error receiving FindContent query response"
                );
                return Err(err.into());
            }
        }
    }

    async fn get_updates(
        &self,
        period: u64,
        count: u8,
    ) -> eyre::Result<Vec<LightClientUpdateCapella>> {
        let updates_key =
            BeaconContentKey::LightClientUpdatesByRange(LightClientUpdatesByRangeKey {
                start_period: period,
                count: count as u64,
            });

        let (tx, rx) = oneshot::channel();

        let overlay_command = OverlayCommand::FindContentQuery {
            target: updates_key,
            callback: tx,
            is_trace: false,
        };

        if let Err(err) = self.overlay_tx.send(overlay_command) {
            warn!(
                protocol = "beacon",
                error = %err,
                "Error submitting FindContent query to service"
            );
            return Err(err.into());
        }

        match rx.await {
            Ok(result) => {
                let content_value = BeaconContentValue::decode(
                    &result
                        .0
                        .ok_or(format!("LightClientUpdatesByRange period={period}, count={count} not found on the network."))
                        .map_err(|err| eyre!("{err}"))?,
                )?;

                if let BeaconContentValue::LightClientUpdatesByRange(updates) = content_value {
                    let capella_updates: Vec<LightClientUpdate> = updates
                        .as_ref()
                        .iter()
                        .map(|update| update.update.clone())
                        .collect();

                    let mut result: Vec<LightClientUpdateCapella> = Vec::new();

                    for update in capella_updates {
                        // Check if updates is LightLCientUpdateCapella
                        if let LightClientUpdate::Capella(update_capella) = update {
                            result.push(update_capella);
                        } else {
                            return Err(eyre!(
                                "Error converting LightClientUpdate to LightClientUpdateCapella"
                            ));
                        }
                    }
                    Ok(result)
                } else {
                    return Err(eyre!(
                        "Error converting BeaconContentValue to LightClientUpdatesByRange"
                    ));
                }
            }
            Err(err) => {
                warn!(
                    protocol = %"beacon",
                    error = %err,
                    "Error receiving FindContent query response"
                );
                return Err(err.into());
            }
        }
    }

    async fn get_finality_update(&self) -> eyre::Result<LightClientFinalityUpdateCapella> {
        let expected_current_slot = expected_current_slot();
        let recent_epoch_start = expected_current_slot - (expected_current_slot % 32) + 1;

        let finality_update_key =
            BeaconContentKey::LightClientFinalityUpdate(LightClientFinalityUpdateKey {
                finalized_slot: recent_epoch_start,
            });

        let (tx, rx) = oneshot::channel();

        let overlay_command = OverlayCommand::FindContentQuery {
            target: finality_update_key,
            callback: tx,
            is_trace: false,
        };

        if let Err(err) = self.overlay_tx.send(overlay_command) {
            warn!(
                protocol = "beacon",
                error = %err,
                "Error submitting FindContent query to service"
            );
            return Err(err.into());
        }

        match rx.await {
            Ok(result) => {
                let finality_update = BeaconContentValue::decode(
                    &result
                        .0
                        .ok_or(format!("LightClientFinalityUpdate content with finalized slot {recent_epoch_start} not found on the network."))
                        .map_err(|err| eyre!("{err}"))?,
                )?;

                if let BeaconContentValue::LightClientFinalityUpdate(finality_update) =
                    finality_update
                {
                    if let LightClientFinalityUpdate::Capella(finality_update_capella) =
                        finality_update.update
                    {
                        Ok(finality_update_capella)
                    } else {
                        return Err(eyre!(
                            "Error converting LightClientFinalityUpdate to LightClientFinalityUpdateCapella"
                        ));
                    }
                } else {
                    return Err(eyre!(
                        "Error converting BeaconContentValue to LightClientFinalityUpdate"
                    ));
                }
            }
            Err(err) => {
                warn!(
                    protocol = %"beacon",
                    error = %err,
                    "Error receiving FindContent query response"
                );
                return Err(err.into());
            }
        }
    }

    async fn get_optimistic_update(&self) -> eyre::Result<LightClientOptimisticUpdateCapella> {
        let expected_current_slot = expected_current_slot();
        let optimistic_update_key =
            BeaconContentKey::LightClientOptimisticUpdate(LightClientOptimisticUpdateKey {
                signature_slot: expected_current_slot,
            });

        let (tx, rx) = oneshot::channel();

        let overlay_command = OverlayCommand::FindContentQuery {
            target: optimistic_update_key,
            callback: tx,
            is_trace: false,
        };

        if let Err(err) = self.overlay_tx.send(overlay_command) {
            warn!(
                protocol = "beacon",
                error = %err,
                "Error submitting FindContent query to service"
            );
            return Err(err.into());
        }

        match rx.await {
            Ok(result) => {
                let optimistic_update = BeaconContentValue::decode(
                    &result
                        .0
                        .ok_or(format!("LightClientOptimisticUpdate content with signature slot {expected_current_slot} not found on the network."))
                        .map_err(|err| eyre!("{err}"))?,
                )?;

                if let BeaconContentValue::LightClientOptimisticUpdate(optimistic_update) =
                    optimistic_update
                {
                    if let LightClientOptimisticUpdate::Capella(optimistic_update_capella) =
                        optimistic_update.update
                    {
                        Ok(optimistic_update_capella)
                    } else {
                        return Err(eyre!(
                            "Error converting LightClientOptimisticUpdate to LightClientOptimisticUpdateCapella"
                        ));
                    }
                } else {
                    return Err(eyre!(
                        "Error converting BeaconContentValue to LightClientOptimisticUpdate"
                    ));
                }
            }
            Err(err) => {
                warn!(
                    protocol = %"beacon",
                    error = %err,
                    "Error receiving FindContent query response"
                );
                return Err(err.into());
            }
        }
    }

    async fn chain_id(&self) -> eyre::Result<u64> {
        Ok(1)
    }

    fn name(&self) -> String {
        "portal".to_string()
    }
}

pub fn expected_current_slot() -> u64 {
    let now = SystemTime::now();
    let now = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
    let since_genesis = now - Duration::from_secs(BEACON_GENESIS_TIME);

    since_genesis.as_secs() / 12
}
