use std::{collections::HashSet, str::FromStr};

use tracing::{info, trace};

use ethportal_api::{
    jsonrpsee::core::Error,
    types::{enr::Enr, portal::TraceGossipInfo},
    BeaconContentKey, HistoryContentKey,
};

// Trait for tracking / reporting gossip stats
pub trait StatsReporter<TContentKey> {
    fn new(number: u64) -> Self;

    fn report(&self);

    fn update(&mut self, _content_key: TContentKey, _results: ContentStats) {}
}

// Struct for tracking gossip stats per slot in beacon bridge
#[derive(Debug, Clone, Default)]
pub struct BeaconSlotStats {
    pub slot_number: u64,
    pub bootstrap: Option<ContentStats>,
    pub update: Option<ContentStats>,
    pub finality_update: Option<ContentStats>,
    pub optimistic_update: Option<ContentStats>,
}

impl StatsReporter<BeaconContentKey> for BeaconSlotStats {
    fn new(slot_number: u64) -> Self {
        Self {
            slot_number,
            ..Default::default()
        }
    }

    fn report(&self) {
        if let Some(stats) = &self.bootstrap {
            info!(
                "GossipReport: slot#{} - bootstrap - {}",
                self.slot_number,
                stats.report()
            );
            trace!(
                "GossipReport: slot#{} - bootstrap - offered {:?}",
                self.slot_number,
                stats.offered
            );
            trace!(
                "GossipReport: slot#{} - bootstrap - accepted {:?}",
                self.slot_number,
                stats.accepted
            );
            trace!(
                "GossipReport: slot#{} - bootstrap - transferred {:?}",
                self.slot_number,
                stats.transferred
            );
        }
        if let Some(stats) = &self.update {
            info!(
                "GossipReport: slot#{} - update - {}",
                self.slot_number,
                stats.report()
            );
            trace!(
                "GossipReport: slot#{} - update - offered {:?}",
                self.slot_number,
                stats.offered
            );
            trace!(
                "GossipReport: slot#{} - update - accepted {:?}",
                self.slot_number,
                stats.accepted
            );
            trace!(
                "GossipReport: slot#{} - update - transferred {:?}",
                self.slot_number,
                stats.transferred
            );
        }
        if let Some(stats) = &self.finality_update {
            info!(
                "GossipReport: slot#{} - finality_update - {}",
                self.slot_number,
                stats.report()
            );
            trace!(
                "GossipReport: slot#{} - finality_update - offered {:?}",
                self.slot_number,
                stats.offered
            );
            trace!(
                "GossipReport: slot#{} - finality_update - accepted {:?}",
                self.slot_number,
                stats.accepted
            );
            trace!(
                "GossipReport: slot#{} - finality_update - transferred {:?}",
                self.slot_number,
                stats.transferred
            );
        }
        if let Some(stats) = &self.optimistic_update {
            info!(
                "GossipReport: slot#{} - optimistic_update - {}",
                self.slot_number,
                stats.report()
            );
            trace!(
                "GossipReport: slot#{} - optimistic_update - offered {:?}",
                self.slot_number,
                stats.offered
            );
            trace!(
                "GossipReport: slot#{} - optimistic_update - accepted {:?}",
                self.slot_number,
                stats.accepted
            );
            trace!(
                "GossipReport: slot#{} - optimistic_update - transferred {:?}",
                self.slot_number,
                stats.transferred
            );
        }
    }

    fn update(&mut self, content_key: BeaconContentKey, results: ContentStats) {
        match content_key {
            BeaconContentKey::LightClientBootstrap(_) => {
                self.bootstrap = Some(results);
            }
            BeaconContentKey::LightClientUpdatesByRange(_) => {
                self.update = Some(results);
            }
            BeaconContentKey::LightClientFinalityUpdate(_) => {
                self.finality_update = Some(results);
            }
            BeaconContentKey::LightClientOptimisticUpdate(_) => {
                self.optimistic_update = Some(results);
            }
        }
    }
}

// Struct for tracking gossip stats per block in history bridge
#[derive(Debug, Clone, Default)]
pub struct HistoryBlockStats {
    pub block_number: u64,
    pub header_with_proof: Option<ContentStats>,
    pub block_body: Option<ContentStats>,
    pub receipts: Option<ContentStats>,
    pub epoch_accumulator: Option<ContentStats>,
}

impl StatsReporter<HistoryContentKey> for HistoryBlockStats {
    fn new(block_number: u64) -> Self {
        Self {
            block_number,
            ..Default::default()
        }
    }

    fn report(&self) {
        if let Some(stats) = &self.header_with_proof {
            info!(
                "GossipReport: block#{}: header_with_proof - {}",
                self.block_number,
                stats.report()
            );
            trace!(
                "GossipReport: block#{}: header_with_proof - offered {:?}",
                self.block_number,
                stats.offered
            );
            trace!(
                "GossipReport: block#{}: header_with_proof - accepted {:?}",
                self.block_number,
                stats.accepted
            );
            trace!(
                "GossipReport: block#{}: header_with_proof - transferred {:?}",
                self.block_number,
                stats.transferred
            );
        }
        if let Some(stats) = &self.block_body {
            info!(
                "GossipReport: block#{}: block_body - {}",
                self.block_number,
                stats.report()
            );
            trace!(
                "GossipReport: block#{}: block_body - offered {:?}",
                self.block_number,
                stats.offered
            );
            trace!(
                "GossipReport: block#{}: block_body - accepted {:?}",
                self.block_number,
                stats.accepted
            );
            trace!(
                "GossipReport: block#{}: block_body - transferred {:?}",
                self.block_number,
                stats.transferred
            );
        }
        if let Some(stats) = &self.receipts {
            info!(
                "GossipReport: block#{}: receipts - {}",
                self.block_number,
                stats.report()
            );
            trace!(
                "GossipReport: block#{}: receipts - offered {:?}",
                self.block_number,
                stats.offered
            );
            trace!(
                "GossipReport: block#{}: receipts - accepted {:?}",
                self.block_number,
                stats.accepted
            );
            trace!(
                "GossipReport: block#{}: receipts - transferred {:?}",
                self.block_number,
                stats.transferred
            );
        }
        if let Some(stats) = &self.epoch_accumulator {
            info!(
                "GossipReport: block#{}: epoch_accumulator - {}",
                self.block_number,
                stats.report()
            );
            trace!(
                "GossipReport: block#{}: epoch_accumulator - offered {:?}",
                self.block_number,
                stats.offered
            );
            trace!(
                "GossipReport: block#{}: epoch_accumulator - accepted {:?}",
                self.block_number,
                stats.accepted
            );
            trace!(
                "GossipReport: block#{}: epoch_accumulator - transferred {:?}",
                self.block_number,
                stats.transferred
            );
        }
    }

    fn update(&mut self, content_key: HistoryContentKey, results: ContentStats) {
        match content_key {
            HistoryContentKey::BlockHeaderWithProof(_) => {
                self.header_with_proof = Some(results);
            }
            HistoryContentKey::BlockBody(_) => {
                self.block_body = Some(results);
            }
            HistoryContentKey::BlockReceipts(_) => {
                self.receipts = Some(results);
            }
            HistoryContentKey::EpochAccumulator(_) => {
                self.epoch_accumulator = Some(results);
            }
        }
    }
}

// Struct to record the gossip stats for a single piece of content (eg key/value pair),
// consolidating results from jsonrpc requests to 1/many clients.
//
// After implementing retries on gossip, it's often the case that we offer the same piece
// of content to the same peer multiple times, however, we only record unique enrs in these lists.
// Currently, this is just to simplify, but if there's a use case where it makes sense to record
// duplicate offers to the same peer, we can change this, by removing the double count check in the
// From impl below.
#[derive(Debug, Clone, Default)]
pub struct ContentStats {
    // use hashset so peers aren't double-counted across clients
    pub offered: HashSet<Enr>,
    pub accepted: HashSet<Enr>,
    pub transferred: HashSet<Enr>,
    pub retries: u64,
    pub failures: u64,
}

impl ContentStats {
    pub fn report(&self) -> String {
        format!(
            "offered: {}, accepted: {}, transferred: {}, retries: {}, failures: {}",
            self.offered.len(),
            self.accepted.len(),
            self.transferred.len(),
            self.retries,
            self.failures,
        )
    }
}

impl From<Vec<Result<(Vec<TraceGossipInfo>, u64), Error>>> for ContentStats {
    fn from(results: Vec<Result<(Vec<TraceGossipInfo>, u64), Error>>) -> Self {
        let mut content_stats = ContentStats::default();
        for trace_gossip_info in results.iter() {
            match trace_gossip_info {
                Ok((traces, retries)) => {
                    content_stats.retries += retries;
                    for trace in traces {
                        for enr in trace.offered.iter() {
                            let enr = Enr::from_str(enr)
                                .expect("ENR from trace gossip response to successfully decode.");
                            content_stats.offered.insert(enr);
                        }

                        for enr in trace.accepted.iter() {
                            let enr = Enr::from_str(enr)
                                .expect("ENR from trace gossip response to successfully decode.");
                            content_stats.accepted.insert(enr);
                        }

                        for enr in trace.transferred.iter() {
                            let enr = Enr::from_str(enr)
                                .expect("ENR from trace gossip response to successfully decode.");
                            content_stats.transferred.insert(enr);
                        }
                    }
                }
                Err(_) => content_stats.failures += 1,
            }
        }
        content_stats
    }
}
