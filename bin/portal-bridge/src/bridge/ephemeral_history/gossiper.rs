use std::{sync::Arc, time::Instant};

use alloy::consensus::Header;
use ethereum_rpc_client::consensus::ConsensusApi;
use ethportal_api::{
    consensus::{beacon_block::BeaconBlockElectra, beacon_state::HistoricalBatch},
    types::{
        execution::{
            builders::block::ExecutionBlockBuilder, ephermeral_header::EphemeralHeaderOffer,
        },
        network::Subnetwork,
        portal_wire::{OfferTrace, OfferTraceMultipleItems},
    },
    ContentValue, LegacyHistoryContentKey, LegacyHistoryContentValue, OverlayContentKey,
    RawContentKey, RawContentValue,
};
use futures::future::join_all;
use revm_primitives::B256;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tracing::{error, info, warn};
use trin_legacy_history::network::LegacyHistoryNetwork;
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
    history_network: Arc<LegacyHistoryNetwork>,
    /// Records and reports bridge metrics
    metrics: BridgeMetricsReporter,
    /// Semaphore used to limit the number of concurrent offers sent at the head of the chain
    head_semaphore: Arc<Semaphore>,
    /// Semaphore used to limit the number of non ephemeral headers gossiped at once
    non_ephemeral_headers_semaphore: Arc<Semaphore>,
}

impl Gossiper {
    pub fn new(
        census: Census,
        history_network: Arc<LegacyHistoryNetwork>,
        metrics: BridgeMetricsReporter,
        head_offer_limit: usize,
        non_ephemeral_offer_limit: usize,
    ) -> Self {
        Self {
            census,
            history_network,
            metrics,
            head_semaphore: Arc::new(Semaphore::new(head_offer_limit)),
            non_ephemeral_headers_semaphore: Arc::new(Semaphore::new(non_ephemeral_offer_limit)),
        }
    }

    /// Gossips the EphemeralBundle.
    ///
    /// Starts with gossiping the header series
    /// It waits for [HEADER_SATURATION_DELAY] then gossiping BlockBody and BlockReceipts.
    ///
    /// Finishes once all content is gossiped.
    pub async fn gossip_ephemeral_bundle(&self, ephemeral_bundle: EphemeralBundle) {
        info!(
            head_block_root = %ephemeral_bundle.head_beacon_block_root,
            block_count = %ephemeral_bundle.blocks.len(),
            "Gossiping ephemeral bundle"
        );

        let mut headers = vec![];
        let mut bodies = vec![];
        let mut receipts = vec![];
        for (header, body, receipt) in ephemeral_bundle.blocks {
            let block_hash = header.hash_slow();
            bodies.push((block_hash, body));
            receipts.push((block_hash, receipt));
            headers.push(header);
        }

        // Gossip header series and wait until it finishes
        self.gossip_content_header_series(headers).await;

        let mut gossip_tasks = vec![];

        // Wait until the header series saturates network,
        // since it must be available for body / receipt validation
        sleep(HEADER_SATURATION_DELAY).await;

        // Start gossiping BlockBody and BlockReceipts
        for (block_hash, body) in bodies {
            let content_key = LegacyHistoryContentKey::new_block_body(block_hash);
            let content_value = LegacyHistoryContentValue::BlockBody(body);
            gossip_tasks.push(self.start_gossip_task(content_key, content_value, true));
        }
        for (block_hash, receipts) in receipts {
            let content_key = LegacyHistoryContentKey::new_block_receipts(block_hash);
            let content_value = LegacyHistoryContentValue::Receipts(receipts);
            gossip_tasks.push(self.start_gossip_task(content_key, content_value, true));
        }

        // Wait until BlockBody and BlockReceipts are gossiped
        join_all(gossip_tasks).await;

        info!(
            head_block_root = %ephemeral_bundle.head_beacon_block_root,
            "Finished gossiping ephemeral bundle"
        );
    }

    /// The finalized state root should be for a finalized period. The beacon blocks passed in must
    /// be contained with that respective period's block roots to be provable.
    pub async fn gossiped_non_ephemeral_headers(
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

            let header_by_hash_key = LegacyHistoryContentKey::new_block_header_by_hash(
                header_with_proof.header.hash_slow(),
            );
            let header_by_number_key = LegacyHistoryContentKey::new_block_header_by_number(
                header_with_proof.header.number,
            );
            let content_value = LegacyHistoryContentValue::BlockHeaderWithProof(header_with_proof);
            gossip_tasks.push(self.start_gossip_task(
                header_by_hash_key,
                content_value.clone(),
                false,
            ));
            gossip_tasks.push(self.start_gossip_task(header_by_number_key, content_value, false));
        }

        join_all(gossip_tasks).await;
    }

    /// Starts async task that gossips content, retuning [JoinHandle] for it.
    fn start_gossip_task(
        &self,
        content_key: LegacyHistoryContentKey,
        content_value: LegacyHistoryContentValue,
        is_head_offer: bool,
    ) -> JoinHandle<Vec<OfferTrace>> {
        let gossiper = self.clone();
        tokio::spawn(async move {
            gossiper
                .gossip_content(content_key, content_value, is_head_offer)
                .await
        })
    }

    /// Spawn individual offer tasks for each interested enr found in Census.
    ///
    /// Returns once all tasks complete.
    async fn gossip_content(
        &self,
        content_key: LegacyHistoryContentKey,
        content_value: LegacyHistoryContentValue,
        is_head_offer: bool,
    ) -> Vec<OfferTrace> {
        let Ok(peers) = self
            .census
            .select_peers(Subnetwork::LegacyHistory, &content_key)
        else {
            error!("Failed to request enrs for content key, skipping offer: {content_key:?}");
            return vec![];
        };
        let encoded_content_value = content_value.encode();
        let mut tasks = vec![];
        for peer in peers.clone() {
            let semaphore = if is_head_offer {
                self.head_semaphore.clone()
            } else {
                self.non_ephemeral_headers_semaphore.clone()
            };
            let offer_permit = semaphore
                .acquire_owned()
                .await
                .expect("to be able to acquire semaphore");
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
        content_key: LegacyHistoryContentKey,
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
            Subnetwork::LegacyHistory,
            peer.enr.node_id(),
            content_value_size,
            start_time.elapsed(),
            &offer_trace,
        );

        self.metrics.report_offer(
            match content_key {
                LegacyHistoryContentKey::BlockHeaderByHash(_) => "header_by_hash",
                LegacyHistoryContentKey::BlockHeaderByNumber(_) => "header_by_number",
                LegacyHistoryContentKey::BlockBody(_) => "block_body",
                LegacyHistoryContentKey::BlockReceipts(_) => "receipts",
                LegacyHistoryContentKey::EphemeralHeadersFindContent(_) => {
                    "ephemeral_headers_find_content"
                }
                LegacyHistoryContentKey::EphemeralHeaderOffer(_) => "ephemeral_header_offer",
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
        headers: Vec<Header>,
    ) -> Vec<OfferTraceMultipleItems> {
        let mut content_items = vec![];
        for header in headers {
            content_items.push((
                LegacyHistoryContentKey::new_ephemeral_header_offer(header.hash_slow()).to_bytes(),
                LegacyHistoryContentValue::EphemeralHeaderOffer(EphemeralHeaderOffer { header })
                    .encode(),
            ));
        }

        let Ok(peers) = self.census.select_random_peers(Subnetwork::LegacyHistory) else {
            error!("Failed to request enrs for content key, this is unexpected");
            return vec![];
        };
        let mut tasks = vec![];
        for peer in peers.clone() {
            let offer_permit = self
                .head_semaphore
                .clone()
                .acquire_owned()
                .await
                .expect("to be able to acquire semaphore");

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

        // todo: add census record offer result for multiple items https://github.com/ethereum/trin/issues/1861

        // todo: add metrics report offer for multiple items https://github.com/ethereum/trin/issues/1862

        self.metrics.stop_process_timer(timer);
        // Release permit
        drop(offer_permit);

        offer_trace
    }
}
