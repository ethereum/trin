use std::path::PathBuf;

use anyhow::ensure;
use e2store::e2hs::{E2HSWriter, BLOCKS_PER_E2HS};
use ethportal_api::consensus::{beacon_block::BeaconBlockElectra, beacon_state::HistoricalBatch};
use ssz_types::FixedVector;
use tempfile::TempDir;
use tracing::info;
use trin_validation::{
    constants::{CAPELLA_FORK_EPOCH, SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT},
    header_validator::HeaderValidator,
};

use super::ethereum_api::EthereumApi;
use crate::{
    cli::HeadGeneratorConfig,
    subcommands::{execution_block_builder::ExecutionBlockBuilder, full_block::FullBlock},
};

pub struct ProvingAnchors {
    current_historical_batch: HistoricalBatch,
    current_historical_summaries_index: u64,
    header_validator: HeaderValidator,
}

impl ProvingAnchors {
    /// Create a new instance of ProvingAnchors.
    ///
    /// This function initializes the struct with default values. `update_proving_anchors` must be
    /// called to initialize the proving anchors.
    pub fn new() -> Self {
        Self {
            current_historical_batch: HistoricalBatch {
                block_roots: FixedVector::default(),
                state_roots: FixedVector::default(),
            },
            current_historical_summaries_index: 0,
            header_validator: HeaderValidator::new_with_historical_summaries(Default::default()),
        }
    }
}

pub struct E2HSBuilder {
    pub ethereum_api: EthereumApi,
    temp_dir: TempDir,
    slot_for_next_execution_number: u64,
    pub index: u64,
    proving_anchors: ProvingAnchors,
}

impl E2HSBuilder {
    pub async fn new(config: HeadGeneratorConfig, index: u64) -> anyhow::Result<Self> {
        let ethereum_api = EthereumApi::new(
            config.cl_provider,
            config.el_provider,
            config.request_timeout,
        )
        .await?;

        let next_execution_block_number = index * BLOCKS_PER_E2HS as u64;
        let slot_for_next_execution_number = ethereum_api
            .find_slot_for_execution_block_number(next_execution_block_number)
            .await?;

        Ok(Self {
            ethereum_api,
            slot_for_next_execution_number,
            index,
            temp_dir: TempDir::new()
                .map_err(|err| anyhow::anyhow!("Failed to create temp dir: {err}"))?,
            proving_anchors: ProvingAnchors::new(),
        })
    }

    pub async fn build_e2hs_file(&mut self) -> anyhow::Result<PathBuf> {
        info!("Building E2HS file for index {}", self.index);
        let mut e2hs_writer = E2HSWriter::create(self.temp_dir.path(), self.index)?;

        let starting_block = self.index * BLOCKS_PER_E2HS as u64;
        let ending_block = starting_block + BLOCKS_PER_E2HS as u64;

        for block_number in starting_block..ending_block {
            let beacon_block = self
                .ethereum_api
                .fetch_beacon_block_retry(self.slot_for_next_execution_number)
                .await?
                .message;
            self.update_proving_anchors(beacon_block.slot).await?;
            let block = self.build_block(block_number, &beacon_block).await?;
            block
                .validate_block(&self.proving_anchors.header_validator)
                .await?;
            e2hs_writer.append_block_tuple(&block.into())?;

            info!(
                "Fetched block {}/{} ({:.2}%)",
                block_number,
                ending_block,
                ((block_number - starting_block + 1) as f64
                    / (ending_block - starting_block) as f64)
                    * 100.0
            );
            self.slot_for_next_execution_number = beacon_block.slot + 1;
        }

        let e2hs_path = e2hs_writer.finish()?;
        info!("Built E2HS file for index {}: {e2hs_path:?}", self.index);
        self.index += 1;

        Ok(e2hs_path)
    }

    /// If the historical summaries index has changed, update the proving anchors.
    async fn update_proving_anchors(&mut self, slot: u64) -> anyhow::Result<()> {
        let index = historical_summaries_index(slot);
        if index == self.proving_anchors.current_historical_summaries_index {
            return Ok(());
        }

        let state = self
            .ethereum_api
            .get_state_for_start_of_next_period(slot)
            .await?;

        self.proving_anchors.current_historical_summaries_index = index;
        self.proving_anchors.header_validator =
            HeaderValidator::new_with_historical_summaries(state.historical_summaries);
        self.proving_anchors.current_historical_batch = HistoricalBatch {
            block_roots: state.block_roots,
            state_roots: state.state_roots,
        };

        Ok(())
    }

    async fn build_block(
        &self,
        block_number: u64,
        beacon_block: &BeaconBlockElectra,
    ) -> anyhow::Result<FullBlock> {
        ensure!(
            beacon_block.body.execution_payload.block_number == block_number,
            "Block number mismatch"
        );
        let (header_with_proof, body) = ExecutionBlockBuilder::electra(
            beacon_block,
            &self.proving_anchors.current_historical_batch,
        )?;
        let receipts = self.ethereum_api.get_receipts(block_number).await?;

        Ok(FullBlock {
            header_with_proof,
            body,
            receipts,
        })
    }
}

/// Calculate the historical summaries index for a given slot.
pub fn historical_summaries_index(slot: u64) -> u64 {
    (slot - CAPELLA_FORK_EPOCH * SLOTS_PER_EPOCH) / SLOTS_PER_HISTORICAL_ROOT
}
