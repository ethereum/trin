use std::{sync::Arc, time::Instant};

use alloy::rpc::types::Withdrawal;
use ethereum_rpc_client::consensus::ConsensusApi;
use ethportal_api::{
    consensus::{beacon_block::BeaconBlockElectra, beacon_state::HistoricalBatch},
    types::{
        execution::{
            builders::{
                block::{decode_transactions, ExecutionBlockBuilder},
                header::ExecutionHeaderBuilder,
            },
            ephermeral_header::EphemeralHeaderOffer,
            header_with_proof::HeaderWithProof,
        },
        network::Subnetwork,
        portal_wire::{OfferTrace, OfferTraceMultipleItems},
    },
    BlockBody, ContentValue, HistoryContentKey, HistoryContentValue, OverlayContentKey,
    RawContentKey, RawContentValue, Receipts,
};
use futures::future::join_all;
use revm_primitives::B256;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tracing::{error, info, warn};
use trin_history::network::HistoryNetwork;
use trin_metrics::bridge::BridgeMetricsReporter;

use super::ephemeral_bundle::EphemeralBundle;
use crate::{
    bridge::constants::{HEADER_SATURATION_DELAY, SERVE_BLOCK_TIMEOUT},
    census::{peer::PeerInfo, Census},
};

/// Structure that sends offer requests to peers.
///
/// This structure is cheap to clone, which makes it easy to use with tokio tasks.
#[derive(Clone)]
pub struct Gossiper {
    /// Used to request all interested enrs in the network.
    census: Census,
    /// Used to send RPC request to trin
    history_network: Arc<HistoryNetwork>,
    /// Records and reports bridge metrics
    metrics: BridgeMetricsReporter,
    /// Semaphore used to limit the number of active offer transfers, in order to make sure we
    /// don't overwhelm the trin client
    offer_semaphore: Arc<Semaphore>,
}

impl Gossiper {
    pub fn new(
        census: Census,
        history_network: Arc<HistoryNetwork>,
        metrics: BridgeMetricsReporter,
        offer_limit: usize,
    ) -> Self {
        Self {
            census,
            history_network,
            metrics,
            offer_semaphore: Arc::new(Semaphore::new(offer_limit)),
        }
    }

    /// Gossips the EphemeralBundle.
    ///
    /// Starts with gossiping the header series
    /// It waits for [HEADER_SATURATION_DELAY] then gossiping BlockBody and BlockReceipts.
    ///
    /// Finishes once all content is gossiped.
    pub async fn gossip_ephemeral_bundle(&self, ephemeral_bundle: EphemeralBundle) {
        info!(head_block_root = %ephemeral_bundle.head_block_root,
            headers_count = %ephemeral_bundle.beacon_blocks.len(),
            bodies_count = %ephemeral_bundle.bodies.len(),
            receipts_count = %ephemeral_bundle.receipts.len(),
            "Gossiping ephemeral bundle"
        );

        // Gossip header series and wait until it finishes
        if let Err(err) = self
            .start_gossip_header_series(ephemeral_bundle.beacon_blocks)
            .await
        {
            error!(%err, "Error while trying to gossip BlockHeaderByHash");
        }

        let mut gossip_tasks = vec![];

        // Wait until the header series saturates network,
        // since it must be available for body / receipt validation
        sleep(HEADER_SATURATION_DELAY).await;

        // Start gossiping BlockBody and BlockReceipts
        for (block_hash, body) in ephemeral_bundle.bodies {
            gossip_tasks.push(self.start_gossip_body_task(block_hash, body));
        }
        for (block_hash, receipts) in ephemeral_bundle.receipts {
            gossip_tasks.push(self.start_gossip_receipts_task(block_hash, receipts));
        }

        // Wait until Header series, BlockBody and BlockReceipts are gossiped
        join_all(gossip_tasks).await;
    }

    fn start_gossip_header_series(
        &self,
        beacon_blocks: Vec<BeaconBlockElectra>,
    ) -> JoinHandle<Vec<OfferTraceMultipleItems>> {
        let mut content_items = vec![];
        for beacon_block in beacon_blocks {
            let payload = &beacon_block.body.execution_payload;
            let transactions =
                decode_transactions(&payload.transactions).expect("Failed to decode transactions");
            let withdrawals = payload
                .withdrawals
                .iter()
                .map(Withdrawal::from)
                .collect::<Vec<_>>();
            let header = ExecutionHeaderBuilder::electra(
                payload,
                beacon_block.parent_root,
                &transactions,
                &withdrawals,
                &beacon_block.body.execution_requests,
            )
            .expect("Failed to build header");

            content_items.push((
                HistoryContentKey::new_ephemeral_header_offer(header.hash_slow()).to_bytes(),
                HistoryContentValue::EphemeralHeaderOffer(EphemeralHeaderOffer { header }).encode(),
            ));
        }

        let executor = self.clone();
        tokio::spawn(async move { executor.gossip_content_header_series(content_items).await })
    }

    fn start_gossip_body_task(
        &self,
        block_hash: B256,
        body: BlockBody,
    ) -> JoinHandle<Vec<OfferTrace>> {
        let content_key = HistoryContentKey::new_block_body(block_hash);
        let content_value = HistoryContentValue::BlockBody(body);
        self.start_gossip_task(content_key, content_value)
    }

    fn start_gossip_receipts_task(
        &self,
        block_hash: B256,
        receipts: Receipts,
    ) -> JoinHandle<Vec<OfferTrace>> {
        let content_key = HistoryContentKey::new_block_receipts(block_hash);
        let content_value = HistoryContentValue::Receipts(receipts);
        self.start_gossip_task(content_key, content_value)
    }

    /// The finalized state root should be for a finalized period. The beacon blocks passed in must
    /// be contained with that respective period's block roots to be provable.
    pub async fn gossiped_proven_headers(
        &self,
        finalized_period_state_root: B256,
        beacon_blocks: Vec<BeaconBlockElectra>,
        consensus_api: ConsensusApi,
    ) {
        let state = consensus_api
            .get_beacon_state(finalized_period_state_root.to_string())
            .await
            .expect("Failed to get beacon state");

        let historical_batch = HistoricalBatch {
            block_roots: state.block_roots,
            state_roots: state.state_roots,
        };

        let mut gossip_tasks = vec![];
        for beacon_block in beacon_blocks {
            let (header_with_proof, _) =
                ExecutionBlockBuilder::electra(&beacon_block, &historical_batch)
                    .expect("Failed to build header with proof");

            gossip_tasks.push(self.start_gossip_header_by_hash_task(
                header_with_proof.header.hash_slow(),
                header_with_proof.clone(),
            ));
            gossip_tasks.push(self.start_gossip_header_by_number_task(
                header_with_proof.header.number,
                header_with_proof,
            ));
        }

        join_all(gossip_tasks).await;
    }

    fn start_gossip_header_by_hash_task(
        &self,
        block_hash: B256,
        header_with_proof: HeaderWithProof,
    ) -> JoinHandle<Vec<OfferTrace>> {
        let content_key = HistoryContentKey::new_block_header_by_hash(block_hash);
        let content_value = HistoryContentValue::BlockHeaderWithProof(header_with_proof);
        self.start_gossip_task(content_key, content_value)
    }

    fn start_gossip_header_by_number_task(
        &self,
        block_number: u64,
        header_with_proof: HeaderWithProof,
    ) -> JoinHandle<Vec<OfferTrace>> {
        let content_key = HistoryContentKey::new_block_header_by_number(block_number);
        let content_value = HistoryContentValue::BlockHeaderWithProof(header_with_proof);
        self.start_gossip_task(content_key, content_value)
    }

    /// Starts async task that gossips content, retuning [JoinHandle] for it.
    fn start_gossip_task(
        &self,
        content_key: HistoryContentKey,
        content_value: HistoryContentValue,
    ) -> JoinHandle<Vec<OfferTrace>> {
        let executor = self.clone();
        tokio::spawn(async move { executor.gossip_content(content_key, content_value).await })
    }

    /// Spawn individual offer tasks for each interested enr found in Census.
    ///
    /// Returns once all tasks complete.
    async fn gossip_content(
        &self,
        content_key: HistoryContentKey,
        content_value: HistoryContentValue,
    ) -> Vec<OfferTrace> {
        let Ok(peers) = self.census.select_peers(Subnetwork::History, &content_key) else {
            error!("Failed to request enrs for content key, skipping offer: {content_key:?}");
            return vec![];
        };
        let encoded_content_value = content_value.encode();
        let mut tasks = vec![];
        for peer in peers.clone() {
            let offer_permit = self.acquire_offer_permit().await;
            let content_key = content_key.clone();
            let raw_content_value = encoded_content_value.clone();

            let gossiper = self.clone();
            tasks.push(tokio::spawn(async move {
                gossiper
                    .send_offer(offer_permit, peer, content_key, raw_content_value)
                    .await
            }));
        }
        join_all(tasks)
            .await
            .into_iter()
            .map(|task_result| match task_result {
                Ok(offer_trace) => offer_trace,
                Err(err) => {
                    error!("Sending offer task failed: {err}");
                    OfferTrace::Failed
                }
            })
            .collect()
    }

    async fn send_offer(
        &self,
        offer_permit: OwnedSemaphorePermit,
        peer: PeerInfo,
        content_key: HistoryContentKey,
        raw_content_value: RawContentValue,
    ) -> OfferTrace {
        let timer = self.metrics.start_process_timer("history_send_offer");

        let start_time = Instant::now();
        let content_value_size = raw_content_value.len();

        let result = timeout(
            SERVE_BLOCK_TIMEOUT,
            self.history_network.overlay.send_offer_trace(
                peer.enr.clone(),
                content_key.to_bytes(),
                raw_content_value,
            ),
        )
        .await;

        let offer_trace = match result {
            Ok(Ok(result)) => {
                if matches!(result, OfferTrace::Failed) {
                    warn!("Internal error offering to: {}", peer.enr);
                }
                result
            }
            Ok(Err(err)) => {
                warn!("Error offering to: {}, error: {err:?}", peer.enr);
                OfferTrace::Failed
            }
            Err(_) => {
                error!(
                    "trace_offer timed out on history {content_key}: indicating a bug is present"
                );
                OfferTrace::Failed
            }
        };

        self.census.record_offer_result(
            Subnetwork::History,
            peer.enr.node_id(),
            content_value_size,
            start_time.elapsed(),
            &offer_trace,
        );

        self.metrics.report_offer(
            match content_key {
                HistoryContentKey::BlockHeaderByHash(_) => "header_by_hash",
                HistoryContentKey::BlockHeaderByNumber(_) => "header_by_number",
                HistoryContentKey::BlockBody(_) => "block_body",
                HistoryContentKey::BlockReceipts(_) => "receipts",
                HistoryContentKey::EphemeralHeadersFindContent(_) => {
                    "ephemeral_headers_find_content"
                }
                HistoryContentKey::EphemeralHeaderOffer(_) => "ephemeral_header_offer",
            },
            &peer.client_type,
            &offer_trace,
        );

        self.metrics.stop_process_timer(timer);
        // Release permit
        drop(offer_permit);

        offer_trace
    }

    /// Spawn individual offer tasks for header series for random enrs found in Census.
    ///
    /// Returns once all tasks complete.
    async fn gossip_content_header_series(
        &self,
        content_items: Vec<(RawContentKey, RawContentValue)>,
    ) -> Vec<OfferTraceMultipleItems> {
        let Ok(peers) = self.census.select_random_peers(Subnetwork::History) else {
            error!("Failed to request enrs for content key, this is unexpected");
            return vec![];
        };
        let mut tasks = vec![];
        for peer in peers.clone() {
            let offer_permit = self.acquire_offer_permit().await;

            let gossiper = self.clone();
            let content_items = content_items.clone();
            tasks.push(tokio::spawn(async move {
                gossiper
                    .send_offer_with_header_series(offer_permit, peer, content_items)
                    .await
            }));
        }
        join_all(tasks)
            .await
            .into_iter()
            .map(|task_result| match task_result {
                Ok(offer_trace) => offer_trace,
                Err(err) => {
                    error!("Sending offer task failed: {err}");
                    OfferTraceMultipleItems::Failed
                }
            })
            .collect()
    }

    async fn send_offer_with_header_series(
        &self,
        offer_permit: OwnedSemaphorePermit,
        peer: PeerInfo,
        content_items: Vec<(RawContentKey, RawContentValue)>,
    ) -> OfferTraceMultipleItems {
        let timer = self.metrics.start_process_timer("history_send_offer");

        let result = timeout(
            SERVE_BLOCK_TIMEOUT,
            self.history_network
                .overlay
                .send_offer_trace_with_multiple_items(peer.enr.clone(), content_items),
        )
        .await;

        let offer_trace = match result {
            Ok(Ok(result)) => {
                if matches!(result, OfferTraceMultipleItems::Failed) {
                    warn!("Internal error offering to: {}", peer.enr);
                }
                result
            }
            Ok(Err(err)) => {
                warn!("Error offering to: {}, error: {err:?}", peer.enr);
                OfferTraceMultipleItems::Failed
            }
            Err(_) => {
                error!("trace_offer timed out on history  : indicating a bug is present");
                OfferTraceMultipleItems::Failed
            }
        };

        // todo: add census record offer result for multiple items

        // todo: add metrics report offer for multiple items

        self.metrics.stop_process_timer(timer);
        // Release permit
        drop(offer_permit);

        offer_trace
    }

    async fn acquire_offer_permit(&self) -> OwnedSemaphorePermit {
        self.offer_semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("to be able to acquire semaphore")
    }
}
