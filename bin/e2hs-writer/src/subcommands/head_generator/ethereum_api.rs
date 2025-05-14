use anyhow::{anyhow, bail, ensure};
use ethportal_api::{
    consensus::{
        beacon_block::SignedBeaconBlockElectra, beacon_state::BeaconStateElectra,
        constants::SLOTS_PER_HISTORICAL_ROOT,
    },
    Receipts,
};
use portal_bridge::api::{consensus::ConsensusApi, execution::ExecutionApi};
use tracing::warn;
use url::Url;

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
        // The `parent_beacon_block_root` refers to the block root of the *previous* beacon block.
        // To fetch the corresponding beacon block, we must query using the *next* execution block
        // number (i.e., `execution_block_number + 1`), since that's when the parent beacon
        // block is referenced.
        let block = self
            .execution_api
            .get_block(execution_block_number + 1)
            .await?;
        let Some(block_root) = block.header.parent_beacon_block_root else {
            bail!("We should only be able to backfill blocks which contain block root's {execution_block_number}")
        };
        let beacon_block = self
            .consensus_api
            .get_beacon_block(block_root.to_string())
            .await?;
        Ok(beacon_block.message.slot)
    }

    pub async fn get_state_for_start_of_next_period(
        &self,
        slot: u64,
    ) -> anyhow::Result<BeaconStateElectra> {
        // To calculate the historical summaries index, we need to add the
        // SLOTS_PER_HISTORICAL_ROOT, as this slot will be included in the next index
        let mut slot = first_slot_in_a_period(slot + SLOTS_PER_HISTORICAL_ROOT);
        let mut tries = 0;

        // The slot at the start of the period can be skipped, so we need to walk forward until we
        // find the first slot not missed
        let state = loop {
            match self.consensus_api.get_beacon_state(slot.to_string()).await {
                Ok(state) => {
                    // For some reason certain implementations will give us a State before the slot
                    // we requested if the requested slot is skipped
                    if state.slot < slot {
                        warn!("The slot {slot} is skipped, and the CL for some reason gave us the state for a previous slot, trying the next slot");
                        slot += 1;
                        tries += 1;
                        continue;
                    }
                    ensure!(
                        state.slot == slot,
                        "The slot {slot} is not equal to the state slot {}",
                        state.slot
                    );
                    break state;
                }
                Err(err) => {
                    warn!("Failed to get beacon block for slot {slot}, the slot was probably skipped: {err}");
                    tries += 1;
                    ensure!(tries <= 5, "Failed to find a valid block for slot {slot}");
                    slot += 1;
                }
            }
        };

        Ok(state)
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

    /// Fetches the Beacon Block for a given slot.
    ///
    /// Slots can be skipped, so we walk until we find a non-skipped slot.
    ///
    /// The retry limit is 5, because I don't think there is a gap of more than 5 slots in the
    /// beacon chain
    pub async fn fetch_beacon_block_retry(
        &self,
        slot: u64,
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
                    slot += 1;
                }
            }
        };

        Ok(block)
    }
}

/// Calculates the first slot in a period for the given slot.
pub fn first_slot_in_a_period(slot: u64) -> u64 {
    (slot / SLOTS_PER_HISTORICAL_ROOT) * SLOTS_PER_HISTORICAL_ROOT
}
