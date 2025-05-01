use std::cmp::Ordering;

use anyhow::{anyhow, bail, ensure};
use ethportal_api::{
    consensus::{beacon_block::SignedBeaconBlockElectra, beacon_state::BeaconStateElectra},
    Receipts,
};
use portal_bridge::api::{consensus::ConsensusApi, execution::ExecutionApi};
use tracing::warn;
use trin_validation::constants::{SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT};
use url::Url;

use super::constants::MAX_ALLOWED_BLOCK_BACKFILL_SIZE;

pub struct EthereumApi {
    pub consensus_api: ConsensusApi,
    pub execution_api: ExecutionApi,
}

impl EthereumApi {
    pub async fn new(
        cl_provider: Url,
        el_provider: Url,
        request_timeout: u64,
    ) -> anyhow::Result<Self> {
        let consensus_api =
            ConsensusApi::new(cl_provider.clone(), cl_provider.clone(), request_timeout).await?;

        let execution_api =
            ExecutionApi::new(el_provider.clone(), el_provider.clone(), request_timeout).await?;

        Ok(Self {
            consensus_api,
            execution_api,
        })
    }

    pub async fn find_slot_for_execution_block_number(
        &self,
        execution_block_number: u64,
    ) -> anyhow::Result<u64> {
        let mut high = self
            .consensus_api
            .get_beacon_block("finalized")
            .await?
            .message
            .slot;
        let mut low = high - MAX_ALLOWED_BLOCK_BACKFILL_SIZE;

        while low <= high {
            let mid = (low + high) / 2;

            // Slots can be skipped, so the block we get might not be for the original slot we
            // requested
            let block = self
                .fetch_beacon_block_directional_retry(mid, Direction::Forward)
                .await?;
            let mid = block.message.slot;

            match block
                .message
                .body
                .execution_payload
                .block_number
                .cmp(&execution_block_number)
            {
                Ordering::Equal => return Ok(block.message.slot),
                Ordering::Less => low = mid + 1,
                Ordering::Greater => high = mid - 1,
            }
        }

        bail!("Execution block number {execution_block_number} not found in beacon chain")
    }

    pub async fn get_state_for_start_of_next_period(
        &self,
        slot: u64,
    ) -> anyhow::Result<BeaconStateElectra> {
        // To calculate the historical summaries index, we need to add the
        // SLOTS_PER_HISTORICAL_ROOT, as this slot will be included in the next index
        let slot = slot + SLOTS_PER_HISTORICAL_ROOT;
        self.consensus_api
            .get_beacon_state(first_slot_in_a_period(slot).to_string())
            .await
    }

    pub async fn get_receipts(&self, execution_block_number: u64) -> anyhow::Result<Receipts> {
        self.execution_api
            .get_receipts(execution_block_number..=execution_block_number)
            .await?
            .remove(&execution_block_number)
            .ok_or(anyhow!(
                "Failed to get receipts for block number {execution_block_number}"
            ))
    }

    pub async fn latest_provable_execution_number(&self) -> anyhow::Result<u64> {
        let latest_finalized_slot = self
            .consensus_api
            .get_beacon_block("finalized")
            .await?
            .message
            .slot;

        // The historical summaries generate in the first slot of the period, contains the block
        // roots for the last 8192 slots So X - 1 is the first provable slot
        let latest_provable_slot = first_slot_in_a_period(latest_finalized_slot) - 1;
        Ok(self
            .fetch_beacon_block_directional_retry(latest_provable_slot, Direction::Backward)
            .await?
            .message
            .body
            .execution_payload
            .block_number)
    }

    /// Fetches the historical batch for a given slot.
    ///
    /// Slots can be skipped, so we need to supply a direction to retry which would depend on the
    /// context
    ///
    /// The retry limit is 5, because I don't think there is a gap of more than 5 slots in the
    /// beacon chain
    pub async fn fetch_beacon_block_directional_retry(
        &self,
        slot: u64,
        direction: Direction,
    ) -> anyhow::Result<SignedBeaconBlockElectra> {
        let mut tries = 0;
        let mut slot = slot;

        let block = loop {
            match self.consensus_api.get_beacon_block(slot.to_string()).await {
                Ok(block) => break block,
                Err(err) => {
                    warn!("Failed to get beacon block for slot {slot}, the slot was probably skipped: {err}");
                    tries += 1;
                    ensure!(tries <= 5, "Failed to find a valid block for slot {slot}");
                    match direction {
                        Direction::Forward => slot += 1,
                        Direction::Backward => slot -= 1,
                    }
                }
            }
        };

        Ok(block)
    }
}

pub enum Direction {
    Forward,
    Backward,
}

/// Calculates the first slot in a period for the given slot.
pub fn first_slot_in_a_period(slot: u64) -> u64 {
    let epoch = slot / SLOTS_PER_EPOCH;
    (epoch - (epoch % (SLOTS_PER_HISTORICAL_ROOT / SLOTS_PER_EPOCH))) * SLOTS_PER_EPOCH
}
