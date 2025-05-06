use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::primitives::B256;
use anyhow::bail;
use async_trait::async_trait;
use ethportal_api::{
    consensus::light_client::bootstrap::LightClientBootstrap,
    light_client::{
        bootstrap::LightClientBootstrapElectra, finality_update::LightClientFinalityUpdateElectra,
        optimistic_update::LightClientOptimisticUpdateElectra, update::LightClientUpdateElectra,
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
use tokio::sync::mpsc::UnboundedSender;
use tracing::warn;

use crate::consensus::rpc::ConsensusRpc;

pub const BEACON_GENESIS_TIME: u64 = 1606824023;

#[derive(Clone, Debug)]
pub struct PortalRpc {
    overlay_tx: UnboundedSender<OverlayCommand<BeaconContentKey>>,
}

impl PortalRpc {
    pub fn with_portal(overlay_tx: UnboundedSender<OverlayCommand<BeaconContentKey>>) -> Self {
        Self { overlay_tx }
    }

    async fn send_find_content(
        &self,
        content_key: &BeaconContentKey,
        content_type: &str,
    ) -> anyhow::Result<BeaconContentValue> {
        let (tx, rx) = oneshot::channel();

        let overlay_command = OverlayCommand::FindContentQuery {
            target: content_key.clone(),
            callback: tx,
            config: Default::default(),
        };

        if let Err(err) = self.overlay_tx.send(overlay_command) {
            warn!(
                protocol = "beacon",
                content_type,
                error = %err,
                "Error submitting FindContent"
            );
            bail!("Error submitting FindContent for {content_type}: {err}");
        }

        let content_value_bytes = match rx.await {
            Ok(Ok((content_value_bytes, _, _))) => content_value_bytes,
            Ok(Err(err)) => bail!("{content_key:?} not found on the network: {err}"),
            Err(err) => {
                warn!(
                    protocol = "beacon",
                    content_type,
                    error = %err,
                    "Error receiving FindContent"
                );
                bail!("Error receiving FindContent for {content_type}: {err}");
            }
        };
        Ok(BeaconContentValue::decode(
            content_key,
            &content_value_bytes,
        )?)
    }
}

#[async_trait]
impl ConsensusRpc for PortalRpc {
    fn new(_path: &str) -> Self {
        unreachable!("PortalRpc does not use path.")
    }

    async fn get_bootstrap(&self, block_root: B256) -> anyhow::Result<LightClientBootstrapElectra> {
        let bootstrap_key = BeaconContentKey::LightClientBootstrap(LightClientBootstrapKey {
            block_hash: *block_root,
        });

        let content_value = self
            .send_find_content(&bootstrap_key, "LightClientBootstrap")
            .await?;

        let BeaconContentValue::LightClientBootstrap(bootstrap) = content_value else {
            bail!("Error converting BeaconContentValue to LightClientBootstrap");
        };
        let LightClientBootstrap::Electra(bootstrap) = bootstrap.bootstrap else {
            bail!("Error converting LightClientBootstrap to LightClientBootstrapElectra")
        };
        Ok(bootstrap)
    }

    async fn get_updates(
        &self,
        period: u64,
        count: u8,
    ) -> anyhow::Result<Vec<LightClientUpdateElectra>> {
        let updates_key =
            BeaconContentKey::LightClientUpdatesByRange(LightClientUpdatesByRangeKey {
                start_period: period,
                count: count as u64,
            });

        let content_value = self
            .send_find_content(&updates_key, "LightClientUpdatesByRange")
            .await?;

        let BeaconContentValue::LightClientUpdatesByRange(updates) = content_value else {
            bail!("Error converting BeaconContentValue to LightClientUpdatesByRange");
        };
        updates
            .0
            .into_iter()
            .map(|update| {
                let LightClientUpdate::Electra(update) = update.update else {
                    bail!("Error converting LightClientUpdate to LightClientUpdateElectra");
                };
                Ok(update)
            })
            .collect()
    }

    async fn get_finality_update(&self) -> anyhow::Result<LightClientFinalityUpdateElectra> {
        // Get the finality update for the most recent finalized epoch. We use 0 as the finalized
        // slot because the finalized slot is not known at this point and the protocol is
        // designed to return the most recent which is > 0
        let finality_update_key =
            BeaconContentKey::LightClientFinalityUpdate(LightClientFinalityUpdateKey {
                finalized_slot: 0,
            });

        let content_value = self
            .send_find_content(&finality_update_key, "LightClientFinalityUpdate")
            .await?;

        let BeaconContentValue::LightClientFinalityUpdate(finality_update) = content_value else {
            bail!("Error converting BeaconContentValue to LightClientFinalityUpdate");
        };
        let LightClientFinalityUpdate::Electra(finality_update) = finality_update.update else {
            bail!("Error converting LightClientFinalityUpdate to LightClientFinalityUpdateElectra");
        };
        Ok(finality_update)
    }

    async fn get_optimistic_update(&self) -> anyhow::Result<LightClientOptimisticUpdateElectra> {
        let expected_current_slot = expected_current_slot();
        let optimistic_update_key =
            BeaconContentKey::LightClientOptimisticUpdate(LightClientOptimisticUpdateKey {
                signature_slot: expected_current_slot,
            });

        let content_value = self
            .send_find_content(&optimistic_update_key, "LightClientOptimisticUpdate")
            .await?;

        let BeaconContentValue::LightClientOptimisticUpdate(optimistic_update) = content_value
        else {
            bail!("Error converting BeaconContentValue to LightClientOptimisticUpdate");
        };
        let LightClientOptimisticUpdate::Electra(optimistic_update) = optimistic_update.update
        else {
            bail!(
                "Error converting LightClientOptimisticUpdate to LightClientOptimisticUpdateElectra"
            );
        };
        Ok(optimistic_update)
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
