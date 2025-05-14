mod ephemeral_bundle;
mod gossiper;

use std::{collections::BTreeMap, sync::Arc};

use alloy::{
    consensus::BlockBody as AlloyBlockBody,
    rpc::types::{
        beacon::events::{
            ChainReorgEvent, FinalizedCheckpointEvent, HeadEvent, LightClientOptimisticUpdateEvent,
        },
        Withdrawal, Withdrawals,
    },
};
use anyhow::{bail, ensure};
use ephemeral_bundle::EphemeralBundle;
use ethereum_rpc_client::{
    consensus::{
        rpc_types::{DecodedEvent, EventTopics},
        ConsensusApi,
    },
    execution::ExecutionApi,
};
use ethportal_api::{
    consensus::{
        beacon_block::BeaconBlockElectra,
        constants::{SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT},
        header::BeaconBlockHeader,
    },
    types::execution::builders::block::decode_transactions,
    BlockBody,
};
use eventsource_client::SSE;
use futures::StreamExt;
use gossiper::Gossiper;
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
    ephemeral_bundle: Option<EphemeralBundle>,
}

impl EphemeralHistoryBridge {
    pub async fn new(
        history_network: Arc<HistoryNetwork>,
        offer_limit: usize,
        consensus_api: ConsensusApi,
        execution_api: ExecutionApi,
        census: Census,
    ) -> anyhow::Result<Self> {
        let metrics = BridgeMetricsReporter::new("ephemeral".to_string(), "history");
        let gossiper = Gossiper::new(census, history_network, metrics, offer_limit);

        Ok(Self {
            gossiper,
            consensus_api,
            execution_api,
            beacon_blocks: BTreeMap::new(),
            ephemeral_bundle: None,
        })
    }

    pub async fn launch(mut self) {
        info!("Launching Ephemeral History bridge");

        let mut stream = self
            .consensus_api
            .get_events_stream(&[
                EventTopics::Head,
                EventTopics::ChainReorg,
                EventTopics::LightClientOptimisticUpdate,
                EventTopics::FinalizedCheckpoint,
            ])
            .expect("Failed to create event stream");

        while let Some(event) = stream.next().await {
            let event = match event {
                Ok(event) => event,
                Err(err) => {
                    error!("Error receiving event: {err:?}");
                    continue;
                }
            };

            let event = match event {
                SSE::Event(event) => match DecodedEvent::try_from(event) {
                    Ok(event) => event,
                    Err(err) => {
                        error!("Failed to decode event: {err:?}");
                        continue;
                    }
                },
                SSE::Connected(connection_details) => {
                    info!("Connected to SSE stream: {connection_details:?}");
                    continue;
                }
                SSE::Comment(comment) => {
                    info!("Received comment: {comment:?}");
                    continue;
                }
            };

            match event {
                DecodedEvent::ChainReorg(chain_reorg_event) => {
                    info!("Received chain reorg: {chain_reorg_event:?}");

                    match self.process_chain_reorg(chain_reorg_event).await {
                        Ok(ephemeral_bundle) => self.ephemeral_bundle = Some(ephemeral_bundle),
                        Err(err) => error!("Failed to process chain reorg: {err:?}"),
                    }
                }
                DecodedEvent::Head(head_event) => {
                    info!("Received head: {head_event:?}");

                    match self.process_head(head_event).await {
                        Ok(ephemeral_bundle) => self.ephemeral_bundle = Some(ephemeral_bundle),
                        Err(err) => error!("Failed to process head: {err:?}"),
                    }
                }
                DecodedEvent::LightClientOptimisticUpdate(light_client_optimistic_update_event) => {
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
                DecodedEvent::FinalizedCheckpoint(finalized_checkpoint_event) => {
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

        // apply head
        let mut ephemeral_bundle = EphemeralBundle::new(chain_reorg_event.new_head_block);
        let mut parent_root = self
            .download_block(chain_reorg_event.new_head_block, &mut ephemeral_bundle)
            .await?;

        // apply reorg
        for _ in 0..chain_reorg_event.depth {
            parent_root = self
                .download_block(parent_root, &mut ephemeral_bundle)
                .await?;
        }

        // apply buffer headers
        self.append_8_buffer_headers(&mut ephemeral_bundle).await?;

        verify_block_series(&ephemeral_bundle.beacon_blocks)?;

        Ok(ephemeral_bundle)
    }

    async fn process_head(&mut self, head_event: HeadEvent) -> anyhow::Result<EphemeralBundle> {
        let mut ephemeral_bundle = EphemeralBundle::new(head_event.block);
        self.download_block(head_event.block, &mut ephemeral_bundle)
            .await?;
        self.append_8_buffer_headers(&mut ephemeral_bundle).await?;
        verify_block_series(&ephemeral_bundle.beacon_blocks)?;

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
            ephemeral_bundle.head_block_root == beacon_block.tree_hash_root(),
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
                    .gossiped_proven_headers(
                        finalized_checkpoint_event.state,
                        blocks,
                        consensus_api,
                    )
                    .await;
            })));
        }

        Ok(None)
    }

    /// Downloads the block from the consensus layer and adds it to the ephemeral bundle.
    ///
    /// returns the parent root of the block.
    async fn download_block(
        &mut self,
        block_root: B256,
        ephemeral_bundle: &mut EphemeralBundle,
    ) -> anyhow::Result<B256> {
        let beacon_block = self
            .consensus_api
            .get_beacon_block(block_root.to_string())
            .await?;
        let message = beacon_block.message;
        let transactions = decode_transactions(&message.body.execution_payload.transactions)?;
        let withdrawals = message
            .body
            .execution_payload
            .withdrawals
            .iter()
            .map(Withdrawal::from)
            .collect();
        ephemeral_bundle.push_body(
            message.body.execution_payload.block_hash,
            BlockBody(AlloyBlockBody {
                transactions,
                ommers: vec![],
                withdrawals: Some(Withdrawals::new(withdrawals)),
            }),
        );
        ephemeral_bundle.push_receipts(
            message.body.execution_payload.block_hash,
            self.execution_api
                .get_receipts(message.body.execution_payload.block_number)
                .await?,
        );

        ensure!(
            block_root == message.tree_hash_root(),
            "Block root does not match: {block_root} != {}",
            message.tree_hash_root()
        );

        let parent_root = message.parent_root;
        self.beacon_blocks
            .insert(message.tree_hash_root(), message.clone());
        ephemeral_bundle.push_beacon_block(message);

        Ok(parent_root)
    }

    async fn append_8_buffer_headers(
        &mut self,
        ephemeral_bundle: &mut EphemeralBundle,
    ) -> anyhow::Result<()> {
        let Some(last_beacon_block) = ephemeral_bundle.beacon_blocks.last() else {
            bail!("No beacon blocks in ephemeral bundle, well applying buffer headers");
        };

        let mut parent_root = last_beacon_block.parent_root;
        for _ in 0..BUFFER_HEADER_COUNT {
            let beacon_block = if let Some(beacon_block) = self.beacon_blocks.get(&parent_root) {
                beacon_block.clone()
            } else if let Ok(beacon_block) = self
                .consensus_api
                .get_beacon_block(parent_root.to_string())
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
            ensure!(
                parent_root == beacon_block.tree_hash_root(),
                "Parent root does not match: {parent_root} != {}",
                beacon_block.tree_hash_root()
            );
            parent_root = beacon_block.parent_root;
            ephemeral_bundle.push_beacon_block(beacon_block);
        }

        Ok(())
    }
}

fn verify_block_series(beacon_blocks: &[BeaconBlockElectra]) -> anyhow::Result<()> {
    let mut parent_root = None;
    for beacon_block in beacon_blocks.iter() {
        if parent_root.is_none() {
            parent_root = Some(beacon_block.parent_root);
        } else {
            ensure!(
                parent_root == Some(beacon_block.tree_hash_root()),
                "Block series validation failed",
            );
            parent_root = Some(beacon_block.parent_root);
        }
    }
    Ok(())
}
