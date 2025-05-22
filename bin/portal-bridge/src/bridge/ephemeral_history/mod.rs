mod ephemeral_bundle;
mod gossiper;

use std::{collections::BTreeMap, num::NonZero, sync::Arc};

use alloy::rpc::types::beacon::events::{
    BeaconNodeEventTopic, ChainReorgEvent, FinalizedCheckpointEvent, HeadEvent,
    LightClientOptimisticUpdateEvent,
};
use anyhow::{bail, ensure};
use ephemeral_bundle::EphemeralBundle;
use ethereum_rpc_client::{
    consensus::{event::BeaconEvent, ConsensusApi},
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

const BUFFER_HEADER_COUNT: u64 = 8;

pub struct EphemeralHistoryBridge {
    /// Gossips the content.
    ///
    /// Creates tasks responsible to gossiping the content, but gossip rate is limited with
    /// [Gossiper::offer_semaphore].
    gossiper: Gossiper,
    consensus_api: ConsensusApi,
    execution_api: ExecutionApi,
    beacon_blocks: BTreeMap<B256, BeaconBlockElectra>,
    receipts: LruCache<u64, Receipts>,
    ephemeral_bundle: Option<EphemeralBundle>,
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
            // We use a cache of 2x SLOTS_PER_EPOCH to ensure we have enough space for the for the
            // receipts
            receipts: LruCache::new(
                NonZero::new(SLOTS_PER_EPOCH as usize * 2).expect("Should be non-zero"),
            ),
            ephemeral_bundle: None,
        })
    }

    pub async fn launch(mut self) {
        info!("Launching Ephemeral History bridge");

        let mut stream = self
            .consensus_api
            .get_events_stream(
                &[
                    BeaconNodeEventTopic::Head,
                    BeaconNodeEventTopic::ChainReorg,
                    BeaconNodeEventTopic::LightClientOptimisticUpdate,
                    BeaconNodeEventTopic::FinalizedCheckpoint,
                ],
                "ephemeral_history_bridge",
            )
            .expect("Failed to create event stream");

        while let Some(event) = stream.next().await {
            match event {
                BeaconEvent::ChainReorg(chain_reorg_event) => {
                    info!("Received chain reorg: {chain_reorg_event:?}");

                    match self.process_chain_reorg(chain_reorg_event).await {
                        Ok(ephemeral_bundle) => self.ephemeral_bundle = Some(ephemeral_bundle),
                        Err(err) => error!("Failed to process chain reorg: {err:?}"),
                    }
                }
                BeaconEvent::Head(head_event) => {
                    info!("Received head: {head_event:?}");

                    match self.process_head(head_event).await {
                        Ok(ephemeral_bundle) => self.ephemeral_bundle = Some(ephemeral_bundle),
                        Err(err) => error!("Failed to process head: {err:?}"),
                    }
                }
                BeaconEvent::LightClientOptimisticUpdate(light_client_optimistic_update_event) => {
                    info!("Received light client optimistic update: {light_client_optimistic_update_event:?}");

                    if let Err(err) = self
                        .process_light_client_optimistic_update(
                            light_client_optimistic_update_event,
                        )
                        .await
                    {
                        error!("Failed to process light client optimistic update: {err:?}");
                    }
                }
                BeaconEvent::FinalizedCheckpoint(finalized_checkpoint_event) => {
                    info!("Received finalized checkpoint: {finalized_checkpoint_event:?}");

                    if let Err(err) = self
                        .process_finalized_checkpoint(finalized_checkpoint_event)
                        .await
                    {
                        error!("Failed to process finalized checkpoint: {err:?}");
                    }
                }
            }
        }
    }

    async fn process_chain_reorg(
        &mut self,
        chain_reorg_event: ChainReorgEvent,
    ) -> anyhow::Result<EphemeralBundle> {
        // clear reorged blocks
        let mut target_root = chain_reorg_event.old_head_block;
        for _ in 0..chain_reorg_event.depth {
            if let Some(beacon_block) = self.beacon_blocks.remove(&target_root) {
                target_root = beacon_block.parent_root;
            }
        }

        let mut ephemeral_bundle = EphemeralBundle::new(chain_reorg_event.new_head_block);

        // apply head + reorg
        for _ in 0..(1 + chain_reorg_event.depth) {
            self.download_next_block_for_ephemeral_bundle(&mut ephemeral_bundle)
                .await?;
        }

        // apply buffer headers
        self.append_8_buffer_headers(&mut ephemeral_bundle).await?;

        Ok(ephemeral_bundle)
    }

    async fn process_head(&mut self, head_event: HeadEvent) -> anyhow::Result<EphemeralBundle> {
        let mut ephemeral_bundle = EphemeralBundle::new(head_event.block);
        self.download_next_block_for_ephemeral_bundle(&mut ephemeral_bundle)
            .await?;
        self.append_8_buffer_headers(&mut ephemeral_bundle).await?;

        Ok(ephemeral_bundle)
    }

    async fn process_light_client_optimistic_update(
        &mut self,
        light_client_event: LightClientOptimisticUpdateEvent,
    ) -> anyhow::Result<JoinHandle<()>> {
        let Some(ephemeral_bundle) = self.ephemeral_bundle.take() else {
            warn!("Ephemeral bundle is not set");
            return Ok(tokio::spawn(async {}));
        };
        let alloy_beacon_block = light_client_event.data.attested_header.beacon;
        let beacon_block = BeaconBlockHeader {
            slot: alloy_beacon_block.slot,
            proposer_index: alloy_beacon_block.proposer_index,
            parent_root: alloy_beacon_block.parent_root,
            state_root: alloy_beacon_block.state_root,
            body_root: alloy_beacon_block.body_root,
        };
        ensure!(
            ephemeral_bundle.head_beacon_block_root == beacon_block.tree_hash_root(),
            "Head block root does not match, this indicates a bug in the bundle creation logic"
        );

        let gossiper = self.gossiper.clone();
        Ok(tokio::spawn(async move {
            gossiper.gossip_ephemeral_bundle(ephemeral_bundle).await;
        }))
    }

    async fn process_finalized_checkpoint(
        &mut self,
        finalized_checkpoint_event: FinalizedCheckpointEvent,
    ) -> anyhow::Result<Option<JoinHandle<()>>> {
        if finalized_checkpoint_event.epoch % (SLOTS_PER_HISTORICAL_ROOT / SLOTS_PER_EPOCH) == 0 {
            let mut blocks = vec![];

            // The finalized period proves the last 8192 slots, it can't be proven until the next
            // cycle
            let Some(beacon_block) = self.beacon_blocks.get(&finalized_checkpoint_event.block)
            else {
                bail!(
                    "Beacon block not found for finalized checkpoint, this is a critical bug: {:?}",
                    finalized_checkpoint_event
                );
            };

            let mut last_block_root = beacon_block.parent_root;
            while let Some(beacon_block) = self.beacon_blocks.remove(&last_block_root) {
                last_block_root = beacon_block.parent_root;
                blocks.push(beacon_block);
            }

            let consensus_api = self.consensus_api.clone();
            let gossiper = self.gossiper.clone();
            return Ok(Some(tokio::spawn(async move {
                gossiper
                    .gossiped_non_ephemeral_headers(
                        finalized_checkpoint_event.state,
                        blocks,
                        consensus_api,
                    )
                    .await;
            })));
        }

        Ok(None)
    }

    /// Downloads the next block as indicated by the EphemeralBundle.
    async fn download_next_block_for_ephemeral_bundle(
        &mut self,
        ephemeral_bundle: &mut EphemeralBundle,
    ) -> anyhow::Result<()> {
        let beacon_block = self
            .consensus_api
            .get_beacon_block(ephemeral_bundle.next_parent_root().to_string())
            .await?
            .message;

        ensure!(
            ephemeral_bundle.next_parent_root() == beacon_block.tree_hash_root(),
            "Block root does not match: {} != {}",
            ephemeral_bundle.next_parent_root(),
            beacon_block.tree_hash_root()
        );

        self.beacon_blocks
            .insert(beacon_block.tree_hash_root(), beacon_block.clone());
        let receipts = self
            .execution_api
            .get_receipts(beacon_block.body.execution_payload.block_number)
            .await?;
        self.receipts.push(
            beacon_block.body.execution_payload.block_number,
            receipts.clone(),
        );

        ephemeral_bundle.push_parent(beacon_block, receipts)?;

        Ok(())
    }

    async fn append_8_buffer_headers(
        &mut self,
        ephemeral_bundle: &mut EphemeralBundle,
    ) -> anyhow::Result<()> {
        for _ in 0..BUFFER_HEADER_COUNT {
            let beacon_block = if let Some(beacon_block) =
                self.beacon_blocks.get(&ephemeral_bundle.next_parent_root())
            {
                beacon_block.clone()
            } else if let Ok(beacon_block) = self
                .consensus_api
                .get_beacon_block(ephemeral_bundle.next_parent_root().to_string())
                .await
            {
                self.beacon_blocks.insert(
                    beacon_block.message.tree_hash_root(),
                    beacon_block.message.clone(),
                );
                beacon_block.message
            } else {
                bail!("Beacon block not found well applying buffer headers");
            };

            let receipts = if let Some(receipts) = self
                .receipts
                .get(&beacon_block.body.execution_payload.block_number)
            {
                receipts.clone()
            } else if let Ok(receipts) = self
                .execution_api
                .get_receipts(beacon_block.body.execution_payload.block_number)
                .await
            {
                self.receipts.push(
                    beacon_block.body.execution_payload.block_number,
                    receipts.clone(),
                );
                receipts
            } else {
                bail!("Receipts not found well applying buffer headers");
            };

            ephemeral_bundle.push_parent(beacon_block, receipts)?;
        }

        Ok(())
    }
}
