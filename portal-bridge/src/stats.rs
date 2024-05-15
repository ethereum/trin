use std::{collections::HashSet, str::FromStr};

use tracing::{debug, info};

use crate::gossip::GossipReport;
use ethportal_api::{jsonrpsee::core::Error, types::enr::Enr, BeaconContentKey, HistoryContentKey};

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
    pub historical_summaries_with_proof: Option<ContentStats>,
}

impl StatsReporter<BeaconContentKey> for BeaconSlotStats {
    fn new(slot_number: u64) -> Self {
        Self {
            slot_number,
            ..Default::default()
        }
    }

    fn report(&self) {
        let slot_number = self.slot_number;
        if let Some(stats) = &self.bootstrap {
            info!("GossipReport: slot#{slot_number} - bootstrap - {stats}");
            debug!("GossipReport: slot#{slot_number} - bootstrap - offered {stats:?}");
        }
        if let Some(stats) = &self.update {
            info!("GossipReport: slot#{slot_number} - update - {stats}");
            debug!("GossipReport: slot#{slot_number} - update - offered {stats:?}");
        }
        if let Some(stats) = &self.finality_update {
            info!("GossipReport: slot#{slot_number} - finality_update - {stats}");
            debug!("GossipReport: slot#{slot_number} - finality_update - offered {stats:?}");
        }
        if let Some(stats) = &self.optimistic_update {
            info!("GossipReport: slot#{slot_number} - optimistic_update - {stats}");
            debug!("GossipReport: slot#{slot_number} - optimistic_update - {stats:?}");
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
            BeaconContentKey::HistoricalSummariesWithProof(_) => {
                self.historical_summaries_with_proof = Some(results);
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
        let block_number = self.block_number;
        if let Some(stats) = &self.header_with_proof {
            info!("GossipReport: block#{block_number}: header_with_proof - {stats}");
            debug!("GossipReport: block#{block_number}: header_with_proof - {stats:?}",);
        }
        if let Some(stats) = &self.block_body {
            info!("GossipReport: block#{block_number}: block_body - {stats}");
            debug!("GossipReport: block#{block_number}: block_body - {stats:?}",);
        }
        if let Some(stats) = &self.receipts {
            info!("GossipReport: block#{block_number}: receipts - {stats}");
            debug!("GossipReport: block#{block_number}: receipts - {stats:?}",);
        }
        if let Some(stats) = &self.epoch_accumulator {
            info!("GossipReport: block#{block_number}: epoch_accumulator - {stats}");
            debug!("GossipReport: block#{block_number}: epoch_accumulator - {stats:?}");
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
#[derive(Clone, Default)]
pub struct ContentStats {
    // use hashset so peers aren't double-counted across clients
    pub offered: HashSet<Enr>,
    pub accepted: HashSet<Enr>,
    pub transferred: HashSet<Enr>,
    pub retries: u64,
    pub failures: u64,
    pub found: bool,
}

impl std::fmt::Debug for ContentStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let offered_enrs = self
            .offered
            .iter()
            .map(|enr| enr.to_string())
            .collect::<Vec<String>>();
        let accepted_enrs = self
            .accepted
            .iter()
            .map(|enr| enr.to_string())
            .collect::<Vec<String>>();
        let transferred_enrs = self
            .transferred
            .iter()
            .map(|enr| enr.to_string())
            .collect::<Vec<String>>();
        let message = format!(
            "\noffered: {offered_enrs:?}\naccepted: {accepted_enrs:?}\ntransferred: {transferred_enrs:?}"
        );
        write!(f, "{message}")
    }
}

impl std::fmt::Display for ContentStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "offered: {}, accepted: {}, transferred: {}, retries: {}, failures: {}, found: {}",
            self.offered.len(),
            self.accepted.len(),
            self.transferred.len(),
            self.retries,
            self.failures,
            self.found,
        )
    }
}

impl From<Result<GossipReport, Error>> for ContentStats {
    fn from(result: Result<GossipReport, Error>) -> Self {
        let mut content_stats = ContentStats::default();
        match result {
            Ok(gossip_report) => {
                content_stats.retries += gossip_report.retries;
                content_stats.found = gossip_report.found;
                for trace in &gossip_report.traces {
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
        content_stats
    }
}
