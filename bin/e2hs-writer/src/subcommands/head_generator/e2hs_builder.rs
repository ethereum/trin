use std::path::PathBuf;

use anyhow::{bail, ensure};
use e2store::e2hs::{E2HSWriter, BLOCKS_PER_E2HS};
use ethereum_rpc_client::{consensus::ConsensusApi, execution::ExecutionApi};
use ethportal_api::{
    consensus::{
        beacon_block::BeaconBlockElectra, beacon_state::HistoricalBatch,
        historical_summaries::historical_summary_index,
    },
    types::execution::builders::block::ExecutionBlockBuilder,
};
use ssz_types::FixedVector;
use tempfile::TempDir;
use tracing::info;
use trin_validation::header_validator::HeaderValidator;

use crate::{cli::HeadGeneratorConfig, subcommands::full_block::FullBlock};

struct ProvingAnchors {
    current_historical_batch: HistoricalBatch,
    current_historical_summary_index: usize,
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
            current_historical_summary_index: 0,
            header_validator: HeaderValidator::new_with_historical_summaries(Default::default()),
        }
    }
}

pub struct E2HSBuilder {
    pub consensus_api: ConsensusApi,
    pub execution_api: ExecutionApi,
    pub index: u64,
    slot_for_next_execution_number: u64,
    proving_anchors: ProvingAnchors,
    temp_dir: TempDir,
}

impl E2HSBuilder {
    pub async fn new(config: HeadGeneratorConfig, index: u64) -> anyhow::Result<Self> {
        let consensus_api = ConsensusApi::new(
            config.cl_provider.clone(),
            config.cl_provider.clone(),
            config.request_timeout,
        )
        .await?;

        let execution_api = ExecutionApi::new(
            config.el_provider.clone(),
            config.el_provider.clone(),
            config.request_timeout,
        )
        .await?;

        let next_execution_block_number = index * BLOCKS_PER_E2HS as u64;
        let slot_for_next_execution_number = find_slot_for_execution_block_number(
            &execution_api,
            &consensus_api,
            next_execution_block_number,
        )
        .await?;

        Ok(Self {
            consensus_api,
            execution_api,
            index,
            slot_for_next_execution_number,
            proving_anchors: ProvingAnchors::new(),
            temp_dir: TempDir::new()
                .map_err(|err| anyhow::anyhow!("Failed to create temp dir: {err}"))?,
        })
    }

    pub async fn build_e2hs_file(&mut self) -> anyhow::Result<PathBuf> {
        info!("Building E2HS file for index {}", self.index);
        let mut e2hs_writer = E2HSWriter::create(self.temp_dir.path(), self.index)?;

        let starting_block = self.index * BLOCKS_PER_E2HS as u64;
        let ending_block = starting_block + BLOCKS_PER_E2HS as u64;

        for block_number in starting_block..ending_block {
            let beacon_block = self
                .consensus_api
                .find_first_beacon_block(self.slot_for_next_execution_number)
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
        let historical_summary_index = historical_summary_index(slot)
            .expect("Relevant slot must have historical_summary_index");
        if historical_summary_index == self.proving_anchors.current_historical_summary_index {
            return Ok(());
        }

        let state = self
            .consensus_api
            .get_state_for_start_of_next_period(slot)
            .await?;

        self.proving_anchors.current_historical_summary_index = historical_summary_index;
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
        let receipts = self.execution_api.get_receipts(block_number).await?;

        Ok(FullBlock {
            header_with_proof,
            body,
            receipts,
        })
    }
}

pub async fn find_slot_for_execution_block_number(
    execution_api: &ExecutionApi,
    consensus_api: &ConsensusApi,
    execution_block_number: u64,
) -> anyhow::Result<u64> {
    // The `parent_beacon_block_root` refers to the block root of the *previous* beacon block.
    // To fetch the corresponding beacon block, we must query using the *next* execution block
    // number (i.e., `execution_block_number + 1`), since that's when the parent beacon
    // block is referenced.
    let block = execution_api.get_block(execution_block_number + 1).await?;
    let Some(block_root) = block.header.parent_beacon_block_root else {
        bail!("We should only be able to backfill blocks which contain block root's {execution_block_number}")
    };
    let beacon_block = consensus_api
        .get_beacon_block(block_root.to_string())
        .await?;
    Ok(beacon_block.message.slot)
}
