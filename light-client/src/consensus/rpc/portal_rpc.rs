use crate::consensus::rpc::ConsensusRpc;
use anyhow::{anyhow, bail};
use async_trait::async_trait;
use ethportal_api::{
    consensus::light_client::bootstrap::LightClientBootstrap,
    light_client::{
        bootstrap::LightClientBootstrapDeneb, finality_update::LightClientFinalityUpdateDeneb,
        optimistic_update::LightClientOptimisticUpdateDeneb, update::LightClientUpdateDeneb,
    },
    types::{
        consensus::light_client::{
            finality_update::LightClientFinalityUpdate,
            optimistic_update::LightClientOptimisticUpdate, update::LightClientUpdate,
        },
        content_key::beacon::{LightClientFinalityUpdateKey, LightClientOptimisticUpdateKey},
    },
    BeaconContentKey, BeaconContentValue, ContentValue, LightClientBootstrapKey,
    LightClientUpdatesByRangeKey,
};
use futures::channel::oneshot;
use portalnet::overlay::command::OverlayCommand;
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
    ) -> anyhow::Result<LightClientBootstrapDeneb> {
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
                let bootstrap = match result {
                    Ok(result) => BeaconContentValue::decode(&result.0)?,
                    Err(err) => {
                        bail!("LightClientBootstrap content not found on the network: {err}")
                    }
                };
                if let BeaconContentValue::LightClientBootstrap(bootstrap) = bootstrap {
                    if let LightClientBootstrap::Deneb(bootstrap_deneb) = bootstrap.bootstrap {
                        Ok(bootstrap_deneb)
                    } else {
                        bail!("Error converting LightClientBootstrap to LightClientBootstrapDeneb")
                    }
                } else {
                    bail!("Error converting BeaconContentValue to LightClientBootstrap");
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
    ) -> anyhow::Result<Vec<LightClientUpdateDeneb>> {
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
                let content_value = match result {
                    Ok(result) => BeaconContentValue::decode(&result.0)?,
                    Err(err) => {
                        return Err(anyhow!("LightClientUpdatesByRange period={period}, count={count} not found on the network: {err}"));
                    }
                };
                if let BeaconContentValue::LightClientUpdatesByRange(updates) = content_value {
                    let deneb_updates: Vec<LightClientUpdate> = updates
                        .as_ref()
                        .iter()
                        .map(|update| update.update.clone())
                        .collect();

                    let mut result: Vec<LightClientUpdateDeneb> = Vec::new();

                    for update in deneb_updates {
                        // Check if updates is LightLCientUpdateDeneb
                        if let LightClientUpdate::Deneb(update_deneb) = update {
                            result.push(update_deneb);
                        } else {
                            return Err(anyhow!(
                                "Error converting LightClientUpdate to LightClientUpdateDeneb"
                            ));
                        }
                    }
                    Ok(result)
                } else {
                    return Err(anyhow!(
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

    async fn get_finality_update(&self) -> anyhow::Result<LightClientFinalityUpdateDeneb> {
        // Get the finality update for the most recent finalized epoch. We use 0 as the finalized
        // slot because the finalized slot is not known at this point and the protocol is
        // designed to return the most recent which is > 0
        let finality_update_key =
            BeaconContentKey::LightClientFinalityUpdate(LightClientFinalityUpdateKey {
                finalized_slot: 0,
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
                let finality_update = match result {
                    Ok(result) => BeaconContentValue::decode(&result.0)?,
                    Err(err) => {
                        return Err(anyhow!("LightClientFinalityUpdate content with finalized slot 0 not found on the network: {err}"));
                    }
                };
                if let BeaconContentValue::LightClientFinalityUpdate(finality_update) =
                    finality_update
                {
                    if let LightClientFinalityUpdate::Deneb(finality_update_deneb) =
                        finality_update.update
                    {
                        Ok(finality_update_deneb)
                    } else {
                        return Err(anyhow!(
                            "Error converting LightClientFinalityUpdate to LightClientFinalityUpdateDeneb"
                        ));
                    }
                } else {
                    return Err(anyhow!(
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

    async fn get_optimistic_update(&self) -> anyhow::Result<LightClientOptimisticUpdateDeneb> {
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
                let optimistic_update = match result {
                    Ok(result) => BeaconContentValue::decode(&result.0)?,
                    Err(err) => {
                        return Err(anyhow!("LightClientOptimisticUpdate content with signature slot {expected_current_slot} not found on the network: {err}"));
                    }
                };
                if let BeaconContentValue::LightClientOptimisticUpdate(optimistic_update) =
                    optimistic_update
                {
                    if let LightClientOptimisticUpdate::Deneb(optimistic_update_deneb) =
                        optimistic_update.update
                    {
                        Ok(optimistic_update_deneb)
                    } else {
                        return Err(anyhow!(
                            "Error converting LightClientOptimisticUpdate to LightClientOptimisticUpdateDeneb"
                        ));
                    }
                } else {
                    return Err(anyhow!(
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

    async fn chain_id(&self) -> anyhow::Result<u64> {
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
