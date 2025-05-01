use std::path::PathBuf;

use anyhow::ensure;
use e2store::e2hs::E2HSWriter;
use ethportal_api::consensus::beacon_state::HistoricalBatch;
use tempfile::TempDir;
use tracing::info;
use trin_validation::{
    constants::{CAPELLA_FORK_EPOCH, SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT},
    header_validator::HeaderValidator,
};

use super::ethereum_api::{Direction, EthereumApi};
use crate::{
    cli::HeadGeneratorConfig,
    subcommands::{
        handle_beacon_block::get_post_electra_header_and_body,
        single_generator::reader::AllBlockData,
    },
};

pub struct E2HSBuilder {
    pub ethereum_api: EthereumApi,
    temp_dir: TempDir,
    slot_for_next_execution_number: u64,
    current_historical_batch: HistoricalBatch,
    current_historical_summaries_index: u64,
    header_validator: HeaderValidator,
}

impl E2HSBuilder {
    pub async fn new(
        config: HeadGeneratorConfig,
        last_processed_period: u64,
    ) -> anyhow::Result<Self> {
        let ethereum_api = EthereumApi::new(
            config.cl_provider,
            config.el_provider,
            config.request_timeout,
        )
        .await?;

        let next_execution_block_number = (last_processed_period + 1) * SLOTS_PER_HISTORICAL_ROOT;
        let slot_for_next_execution_number = ethereum_api
            .find_slot_for_execution_block_number(next_execution_block_number)
            .await?;

        let state = ethereum_api
            .get_state_for_start_of_next_period(slot_for_next_execution_number)
            .await?;
        let header_validator =
            HeaderValidator::new_with_historical_summaries(state.historical_summaries);
        let current_historical_batch = HistoricalBatch {
            block_roots: state.block_roots,
            state_roots: state.state_roots,
        };

        Ok(Self {
            ethereum_api,
            slot_for_next_execution_number,
            header_validator,
            current_historical_batch,
            temp_dir: TempDir::new()
                .map_err(|err| anyhow::anyhow!("Failed to create temp dir: {err}"))?,
            current_historical_summaries_index: historical_summaries_index(
                slot_for_next_execution_number,
            ),
        })
    }

    pub async fn build_e2hs_file(&mut self, period: u64) -> anyhow::Result<PathBuf> {
        info!("Building E2HS file for period {period}");
        let mut e2hs_writer = E2HSWriter::create(self.temp_dir.path(), period)?;

        let starting_block = period * SLOTS_PER_HISTORICAL_ROOT;
        let ending_block = starting_block + SLOTS_PER_HISTORICAL_ROOT;

        for block_number in starting_block..ending_block {
            let block = self.get_block(block_number).await?;
            self.update_proving_anchors().await?;
            self.validate_block(&block).await?;
            e2hs_writer.append_block_tuple(&block.into())?;

            info!(
                "Fetched block {}/{} ({:.2}%)",
                block_number,
                ending_block,
                ((block_number - starting_block + 1) as f64
                    / (ending_block - starting_block) as f64)
                    * 100.0
            );
        }

        let e2hs_path = e2hs_writer.finish()?;
        info!("Built E2HS file for period {period}: {e2hs_path:?}");

        Ok(e2hs_path)
    }

    /// If the historical summaries index has changed, update the proving anchors.
    pub async fn update_proving_anchors(&mut self) -> anyhow::Result<()> {
        let index = historical_summaries_index(self.slot_for_next_execution_number);
        if index == self.current_historical_summaries_index {
            return Ok(());
        }

        self.current_historical_summaries_index = index;

        let state = self
            .ethereum_api
            .get_state_for_start_of_next_period(self.slot_for_next_execution_number)
            .await?;

        self.header_validator
            .historical_summaries_provider
            .update_historical_summaries(state.historical_summaries);
        self.current_historical_batch = HistoricalBatch {
            block_roots: state.block_roots,
            state_roots: state.state_roots,
        };

        Ok(())
    }

    async fn validate_block(&self, block: &AllBlockData) -> anyhow::Result<()> {
        let header_with_proof = &block.header_with_proof;
        self.header_validator
            .validate_header_with_proof(header_with_proof)
            .await?;
        block
            .body
            .validate_against_header(&header_with_proof.header)?;
        ensure!(
            block.receipts.root() == header_with_proof.header.receipts_root,
            "Receipts root mismatch"
        );
        Ok(())
    }

    async fn get_block(&mut self, block_number: u64) -> anyhow::Result<AllBlockData> {
        let block = self
            .ethereum_api
            .fetch_beacon_block_directional_retry(block_number, Direction::Forward)
            .await?;
        ensure!(
            block.message.body.execution_payload.block_number == block_number,
            "Block number mismatch"
        );
        let (header_with_proof, body) =
            get_post_electra_header_and_body(&block.message, &self.current_historical_batch)?;
        let receipts = self.ethereum_api.get_receipts(block_number).await?;

        Ok(AllBlockData {
            block_number,
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
