use std::sync::Arc;

use ethportal_api::{
    consensus::{
        header::BeaconBlockHeader,
        historical_summaries::{HistoricalSummaries, HistoricalSummary},
    },
    light_client::{
        finality_update::LightClientFinalityUpdate,
        header::{LightClientHeader, LightClientHeaderElectra},
        optimistic_update::LightClientOptimisticUpdate,
        update::LightClientUpdate,
    },
};
use parking_lot::RwLock;
use ssz::Decode;
use store::ChainHeadStore;

use crate::TrinValidationAssets;

mod store;

/// Responsible for maintaining and providing the data at the head of the chain.
///
/// This structure has some main properties:
/// - easy to clone and pass around
/// - none of the functions is async or blocking
#[derive(Clone)]
pub struct ChainHead {
    store: Arc<RwLock<ChainHeadStore>>,
}

impl ChainHead {
    /// Creates new istance that assumes that head of the chain is first Pectra block.
    pub fn new_pectra_defaults() -> Self {
        let pectra_header = pectra_light_client_header();
        Self {
            store: Arc::new(RwLock::new(ChainHeadStore::new(
                pectra_header.clone(),
                pectra_header,
                pectra_historical_summaries(),
            ))),
        }
    }

    /// Returns the latest beacon block header.
    pub fn latest_beacon_header(&self) -> BeaconBlockHeader {
        self.store.read().latest.beacon().clone()
    }

    /// Returns the latest finalized beacon block header.
    pub fn finalized_beacon_header(&self) -> BeaconBlockHeader {
        self.store.read().finalized.beacon().clone()
    }

    /// Returns [HistoricalSummary] that corresponds to the provided slot.
    ///
    /// It returns `None` if slot is pre Capella, or is not yet known.
    pub fn historical_summary(&self, slot: u64) -> Option<HistoricalSummary> {
        self.store.read().historical_summary(slot)
    }

    /// Updates the latest beacon block headers, if newer.
    ///
    /// This functions assumes that update is valid.
    pub fn process_update(&self, update: LightClientUpdate) {
        let mut store = self.store.write();
        store.update_latest_if_newer(update.attested_header());
        store.update_finalized_if_newer(update.finalized_header());
    }

    /// Updates the latest beacon block headers, if newer.
    ///
    /// This functions assumes that update is valid.
    pub fn process_optimistic_update(&self, update: LightClientOptimisticUpdate) {
        self.store
            .write()
            .update_latest_if_newer(update.attested_header());
    }

    /// Updates the latest and finalized beacon block headers, if newer.
    ///
    /// This functions assumes that update is valid.
    pub fn process_finality_update(&self, update: LightClientFinalityUpdate) {
        let mut store = self.store.write();
        store.update_latest_if_newer(update.attested_header());
        store.update_finalized_if_newer(update.finalized_header());
    }

    /// Updates the [HistoricalSummaries], if newer.
    ///
    /// This functions assumes that historical summaries are valid.
    pub fn update_historical_summaries(&self, historical_summaries: HistoricalSummaries) {
        self.store
            .write()
            .update_historical_summaries_if_newer(historical_summaries);
    }
}

/// Returns the [LightClientHeader] that corresponds to the first Pectra block.
///
/// Value is embedded in the codebase.
fn pectra_light_client_header() -> LightClientHeader {
    let header: LightClientHeaderElectra = serde_yaml::from_reader(
        TrinValidationAssets::get("validation_assets/chain_head/pectra_light_client_header.yaml")
            .expect("Should be able to load embedded light client header")
            .data
            .as_ref(),
    )
    .expect("Should be able to deserialize embedded light client header");
    LightClientHeader::Electra(header)
}

/// Returns [HistoricalSummaries] that are created at the first Pectra block.
///
/// Value is embedded in the codebase.
fn pectra_historical_summaries() -> HistoricalSummaries {
    HistoricalSummaries::from_ssz_bytes(
        &TrinValidationAssets::get("validation_assets/chain_head/pectra_historical_summaries.ssz")
            .expect("Should be able to load embedded historical summaries")
            .data,
    )
    .expect("Should be able to decode embedded historical summaries")
}

#[cfg(test)]
mod tests {
    use alloy::primitives::b256;
    use ethportal_api::consensus::{
        constants::{ELECTRA_FORK_EPOCH, SLOTS_PER_EPOCH},
        historical_summaries::{historical_summary_index, HistoricalSummaries},
    };
    use tree_hash::TreeHash;
    use trin_utils::submodules::read_ssz_portal_spec_tests_file;

    #[test]
    fn pectra_light_client_header() {
        let header = super::pectra_light_client_header();
        assert_eq!(header.beacon().slot, ELECTRA_FORK_EPOCH * SLOTS_PER_EPOCH);
        assert_eq!(
            header.beacon().tree_hash_root(),
            b256!("0x9c30624f15e4df4e8f819f89db8b930f36b561b7f70905688ea208d22fb0b822")
        );
    }

    #[test]
    fn pectra_historical_summaries() {
        let historical_summaries = super::pectra_historical_summaries();

        // Check that it has expected number of historical summaries
        let electra_slot = ELECTRA_FORK_EPOCH * SLOTS_PER_EPOCH;
        let expected_historical_summaries_count = historical_summary_index(electra_slot).unwrap();
        assert_eq!(
            historical_summaries.len(),
            expected_historical_summaries_count
        );

        // Check that it partially matches historical summaries from portal_spec_tests repo
        let historical_summaries_from_spec_test: HistoricalSummaries = read_ssz_portal_spec_tests_file(
            "tests/mainnet/history/headers_with_proof/beacon_data/historical_summaries_at_slot_11476992.ssz",
        ).unwrap();

        let common_historical_summaries = usize::min(
            historical_summaries.len(),
            historical_summaries_from_spec_test.len(),
        );

        assert_eq!(
            historical_summaries[..common_historical_summaries],
            historical_summaries_from_spec_test[..common_historical_summaries]
        );
    }
}
