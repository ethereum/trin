mod ephemeral_bundle;
mod gossiper;

use std::{
    collections::{btree_map::Entry, BTreeMap},
    num::NonZero,
    sync::Arc,
};

use alloy::rpc::types::beacon::events::{
    BeaconNodeEventTopic, FinalizedCheckpointEvent, HeadEvent, LightClientOptimisticUpdateEvent,
};
use anyhow::{bail, ensure};
use ephemeral_bundle::EphemeralBundle;
use ethereum_rpc_client::{
    consensus::{event::BeaconEvent, first_slot_in_a_period, ConsensusApi},
    execution::ExecutionApi,
};
use ethportal_api::{
    consensus::{
        beacon_block::BeaconBlockElectra,
        constants::{SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT},
        header::BeaconBlockHeader,
    },
    Receipts,
};
use futures::StreamExt;
use gossiper::Gossiper;
use lru::LruCache;
use revm_primitives::B256;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};
use tree_hash::TreeHash;
use trin_history::network::HistoryNetwork;
use trin_metrics::bridge::BridgeMetricsReporter;

use crate::census::Census;

/// Total number of blocks we need to buffer in the bridge.
/// - 1 for the head block
/// - 4 blocks as wiggle room for re-orgs, re-orgs should never been greater than 7 slots
/// - 8 blocks as a buffer for network stability, if there are any problems on the network this will
///   ensure we are good
const TOTAL_BUFFER_COUNT: u64 = 1 + 4 + 8;

pub struct EphemeralHistoryBridge {
    gossiper: Gossiper,
    consensus_api: ConsensusApi,
    execution_api: ExecutionApi,
    beacon_blocks: BTreeMap<B256, BeaconBlockElectra>,
    receipts: LruCache<u64, Receipts>,
}

impl EphemeralHistoryBridge {
    pub async fn new(
        history_network: Arc<HistoryNetwork>,
        head_offer_limit: usize,
        non_ephemeral_offer_limit: usize,
        consensus_api: ConsensusApi,
        execution_api: ExecutionApi,
        census: Census,
    ) -> anyhow::Result<Self> {
        let metrics = BridgeMetricsReporter::new("ephemeral".to_string(), "history");
        let gossiper = Gossiper::new(
            census,
            history_network,
            metrics,
            head_offer_limit,
            non_ephemeral_offer_limit,
        );

        Ok(Self {
            gossiper,
            consensus_api,
            execution_api,
            beacon_blocks: BTreeMap::new(),
            // We use a cache of 2x SLOTS_PER_EPOCH to ensure we have enough space for the receipts
            receipts: LruCache::new(
                NonZero::new(SLOTS_PER_EPOCH as usize * 2).expect("Should be non-zero"),
            ),
        })
    }

    pub async fn launch(mut self) {
        info!("Launching Ephemeral History bridge");

        let mut stream = self
            .consensus_api
            .get_events_stream(
                &[
                    BeaconNodeEventTopic::Head,
                    BeaconNodeEventTopic::LightClientOptimisticUpdate,
                    BeaconNodeEventTopic::FinalizedCheckpoint,
                ],
                "ephemeral_history_bridge",
            )
            .expect("Failed to create event stream");

        while let Some(event) = stream.next().await {
            match event {
                BeaconEvent::Head(head_event) => {
                    info!(block_root = ?head_event.block, "Received head");

                    if let Err(err) = self.process_head(head_event).await {
                        error!("Failed to process head: {err:?}");
                    }
                }
                BeaconEvent::LightClientOptimisticUpdate(light_client_optimistic_update_event) => {
                    info!(
                        slot = ?light_client_optimistic_update_event
                            .data
                            .attested_header
                            .beacon
                            .slot,
                        "Received light client optimistic update"
                    );

                    if let Err(err) = self.process_light_client_optimistic_update(
                        light_client_optimistic_update_event,
                    ) {
                        error!("Failed to process light client optimistic update: {err:?}");
                    }
                }
                BeaconEvent::FinalizedCheckpoint(finalized_checkpoint_event) => {
                    info!(
                        block_root = ?finalized_checkpoint_event.block,
                        "Received finalized checkpoint"
                    );

                    if let Err(err) = self.process_finalized_checkpoint(finalized_checkpoint_event)
                    {
                        error!("Failed to process finalized checkpoint: {err:?}");
                    }
                }
                _ => warn!("Received unexpected event: {event:?}"),
            }
        }
    }

    async fn process_head(&mut self, head_event: HeadEvent) -> anyhow::Result<()> {
        let mut next_root = head_event.block;
        for _ in 0..TOTAL_BUFFER_COUNT {
            let beacon_block = self.get_or_download_beacon_block(next_root).await?;
            next_root = beacon_block.parent_root;
        }

        Ok(())
    }

    fn process_light_client_optimistic_update(
        &mut self,
        light_client_event: LightClientOptimisticUpdateEvent,
    ) -> anyhow::Result<JoinHandle<()>> {
        if self.beacon_blocks.is_empty() {
            warn!("Received light client optimistic update with no beacon blocks, skipping processing");
            return Ok(tokio::spawn(async {}));
        }

        let alloy_beacon_block = light_client_event.data.attested_header.beacon;
        let beacon_block = BeaconBlockHeader {
            slot: alloy_beacon_block.slot,
            proposer_index: alloy_beacon_block.proposer_index,
            parent_root: alloy_beacon_block.parent_root,
            state_root: alloy_beacon_block.state_root,
            body_root: alloy_beacon_block.body_root,
        };

        let mut ephemeral_bundle = EphemeralBundle::new(beacon_block.tree_hash_root());
        for _ in 0..TOTAL_BUFFER_COUNT {
            self.append_next_block_to_ephemeral_bundle(&mut ephemeral_bundle)?;
        }

        let gossiper = self.gossiper.clone();
        Ok(tokio::spawn(async move {
            gossiper.gossip_ephemeral_bundle(ephemeral_bundle).await;
        }))
    }

    fn process_finalized_checkpoint(
        &mut self,
        finalized_checkpoint_event: FinalizedCheckpointEvent,
    ) -> anyhow::Result<Option<JoinHandle<()>>> {
        if finalized_checkpoint_event.epoch % (SLOTS_PER_HISTORICAL_ROOT / SLOTS_PER_EPOCH) != 0 {
            return Ok(None);
        }

        // The finalized period proves the last 8192 slots, it can't be proven until the next
        // cycle
        let Some(beacon_block) = self.beacon_blocks.get(&finalized_checkpoint_event.block) else {
            bail!(
                "Beacon block not found for finalized checkpoint, this is a critical bug: {:?}",
                finalized_checkpoint_event
            );
        };

        let mut blocks = vec![];
        let mut last_block_root = beacon_block.parent_root;
        let first_slot_in_period =
            first_slot_in_a_period((finalized_checkpoint_event.epoch - 1) * SLOTS_PER_EPOCH);
        while let Some(beacon_block) = self.beacon_blocks.remove(&last_block_root) {
            last_block_root = beacon_block.parent_root;
            let slot = first_slot_in_a_period(beacon_block.slot);
            ensure!(
                slot == first_slot_in_period,
                "Beacon block slot does not match the expected period: {slot:?} != {first_slot_in_period:?}",
            );
            blocks.push(beacon_block);
        }

        // Delete all blocks that are older than finalized epoch.
        // This can happen if there was chain reorg (and maybe in some other unexpected situations).
        self.beacon_blocks
            .retain(|_, block| block.slot >= finalized_checkpoint_event.epoch * SLOTS_PER_EPOCH);

        let consensus_api = self.consensus_api.clone();
        let gossiper = self.gossiper.clone();
        Ok(Some(tokio::spawn(async move {
            gossiper
                .gossiped_non_ephemeral_headers(
                    finalized_checkpoint_event.state,
                    blocks,
                    consensus_api,
                )
                .await;
        })))
    }

    /// Return the [BeaconBlock] for a given beacon block root.
    ///
    /// If beacon block is not already in `self.beacon_blocks`, it downloads it and puts it there.
    async fn get_or_download_beacon_block(
        &mut self,
        beacon_block_root: B256,
    ) -> anyhow::Result<&BeaconBlockElectra> {
        match self.beacon_blocks.entry(beacon_block_root) {
            Entry::Occupied(occupied_beacon_block) => Ok(occupied_beacon_block.into_mut()),
            Entry::Vacant(vacant_beacon_block) => {
                let beacon_block = self
                    .consensus_api
                    .get_beacon_block(beacon_block_root.to_string())
                    .await?
                    .message;

                let receipts = self
                    .execution_api
                    .get_receipts(beacon_block.body.execution_payload.block_number)
                    .await?;

                self.receipts
                    .push(beacon_block.body.execution_payload.block_number, receipts);
                Ok(vacant_beacon_block.insert(beacon_block))
            }
        }
    }

    fn append_next_block_to_ephemeral_bundle(
        &mut self,
        ephemeral_bundle: &mut EphemeralBundle,
    ) -> anyhow::Result<()> {
        let Some(beacon_block) = self
            .beacon_blocks
            .get(&ephemeral_bundle.next_parent_root())
            .cloned()
        else {
            bail!(
                "Beacon block not found for next parent root: {:?}",
                ephemeral_bundle.next_parent_root()
            );
        };

        let Some(receipts) = self
            .receipts
            .get(&beacon_block.body.execution_payload.block_number)
            .cloned()
        else {
            bail!(
                "Receipts not found for block number: {}",
                beacon_block.body.execution_payload.block_number
            );
        };

        ephemeral_bundle.push_parent(beacon_block, receipts)?;

        Ok(())
    }
}
