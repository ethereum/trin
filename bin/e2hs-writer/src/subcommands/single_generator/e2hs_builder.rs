use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use alloy::primitives::B256;
use alloy_hardforks::EthereumHardforks;
use anyhow::{anyhow, bail, ensure};
use async_stream::stream;
use e2store::e2hs::{E2HSWriter, BLOCKS_PER_E2HS};
use ethereum_rpc_client::execution::ExecutionApi;
use ethportal_api::{
    types::{
        execution::{
            accumulator::EpochAccumulator,
            builders::block::ExecutionBlockBuilder,
            header_with_proof::{
                BlockHeaderProof, BlockProofHistoricalHashesAccumulator, HeaderWithProof,
            },
        },
        network_spec::network_spec,
    },
    Receipts,
};
use futures::{Stream, StreamExt};
use ssz::Decode;
use tokio::try_join;
use tracing::info;
use trin_validation::{accumulator::PreMergeAccumulator, header_validator::HeaderValidator};
use url::Url;

use super::provider::EraProvider;
use crate::subcommands::full_block::FullBlock;

// This struct reads all blocks in an index and creates the block data
// along with the corresponding proofs required to create an E2HS file.
pub struct E2HSBuilder {
    starting_block: u64,
    ending_block: u64,
    pre_merge_accumulator: Option<Arc<EpochAccumulator>>,
    era_provider: EraProvider,
    receipts: HashMap<u64, Receipts>,
    header_validator: HeaderValidator,
}

impl E2HSBuilder {
    pub async fn new(
        index: u64,
        pre_merge_accumulator_path: PathBuf,
        el_provider_url: Url,
    ) -> anyhow::Result<Self> {
        let execution_api = ExecutionApi::new(el_provider_url.clone(), el_provider_url, 10).await?;
        let latest_block = execution_api.get_latest_block_number().await?;
        let maximum_index = latest_block / BLOCKS_PER_E2HS as u64;
        ensure!(
            index <= maximum_index,
            "Index {index} is greater than the maximum index {maximum_index}"
        );

        let starting_block = index * BLOCKS_PER_E2HS as u64;
        let pre_merge_accumulator = if network_spec().is_paris_active_at_block(starting_block) {
            None
        } else {
            Some(Arc::new(
                lookup_pre_merge_accumulator(
                    index,
                    &PreMergeAccumulator::default(),
                    &pre_merge_accumulator_path,
                )
                .await?,
            ))
        };

        let ending_block = starting_block + BLOCKS_PER_E2HS as u64;
        let receipts_required = network_spec().is_paris_active_at_block(ending_block);
        let receipts_handle = tokio::spawn(async move {
            if receipts_required {
                execution_api
                    .get_receipts(starting_block..ending_block)
                    .await
            } else {
                Ok(HashMap::new())
            }
        });
        let era_provider_handle = tokio::spawn(async move { EraProvider::new(index).await });
        let (receipts_result, era_provider_result) =
            try_join!(receipts_handle, era_provider_handle)?;
        let receipts = receipts_result?;
        let era_provider = era_provider_result?;

        // If none is returned, there are no headers which require Historical Summaries to prove, so
        // we are good passing in default.
        let historical_summaries = era_provider.get_historical_summaries().unwrap_or_default();
        let header_validator = HeaderValidator::new_with_historical_summaries(historical_summaries);

        Ok(Self {
            starting_block,
            ending_block,
            pre_merge_accumulator,
            receipts,
            era_provider,
            header_validator,
        })
    }

    pub fn iter_blocks(mut self) -> impl Stream<Item = anyhow::Result<FullBlock>> {
        stream! {
            for current_block in self.starting_block..self.ending_block {
                let block = if network_spec().is_paris_active_at_block(current_block) {
                    self.get_post_merge_block_data(current_block)
                } else {
                    self.get_pre_merge_block_data(current_block)
                }?;
                block.validate_block(&self.header_validator).await?;
                yield Ok(block)
            }
        }
    }

    fn get_pre_merge_block_data(&self, block_number: u64) -> anyhow::Result<FullBlock> {
        let tuple = self.era_provider.get_pre_merge(block_number)?;
        let header = tuple.header.header;
        let Some(pre_merge_accumulator) = &self.pre_merge_accumulator else {
            bail!("Pre merge accumulator not found for pre-merge block: {block_number}")
        };
        let proof = PreMergeAccumulator::construct_proof(&header, pre_merge_accumulator)?;
        let proof = BlockProofHistoricalHashesAccumulator::new(proof.into()).map_err(|e| {
            anyhow!("Unable to convert proof to BlockProofHistoricalHashesAccumulator: {e:?}")
        })?;
        let header_with_proof = HeaderWithProof {
            header,
            proof: BlockHeaderProof::HistoricalHashes(proof),
        };
        Ok(FullBlock {
            header_with_proof,
            body: tuple.body.body,
            receipts: tuple.receipts.receipts,
        })
    }

    fn get_post_merge_block_data(&mut self, block_number: u64) -> anyhow::Result<FullBlock> {
        let (block, historical_batch) = self.era_provider.get_post_merge(block_number)?;
        ensure!(
            block.execution_block_number() == block_number,
            "Post-merge block data is for wrong block! Expected: {block_number}, actual: {}",
            block.execution_block_number()
        );

        let (header_with_proof, body) = ExecutionBlockBuilder::build(block, historical_batch)?;

        let receipts = self.get_receipts(block_number, header_with_proof.header.receipts_root)?;

        Ok(FullBlock {
            header_with_proof,
            body,
            receipts,
        })
    }

    /// Returns the receipts for a given block number and receipts root.
    /// After a receipt is retrieved, it is removed from the internal map.
    ///
    /// Errors if receipts are not found for the given block number or if the receipts root does not
    /// match.
    pub fn get_receipts(
        &mut self,
        block_number: u64,
        receipts_root: B256,
    ) -> anyhow::Result<Receipts> {
        let receipts = self
            .receipts
            .remove(&block_number)
            .ok_or_else(|| anyhow!("Receipts not found for block number {block_number}"))?;
        ensure!(receipts.root() == receipts_root, "Receipts root mismatch");
        Ok(receipts)
    }

    pub async fn build_e2hs_file(self, target_dir: PathBuf, index: u64) -> anyhow::Result<()> {
        info!("Writing index {} to {:?}", index, target_dir);
        let mut e2hs_writer = E2HSWriter::create(&target_dir, index)?;
        let mut block_iter = Box::pin(self.iter_blocks());

        while let Some(block) = block_iter.next().await {
            let block = block?;
            info!("Writing block {}", block.header_with_proof.header.number);
            e2hs_writer.append_block_tuple(&block.into())?;
        }

        let e2hs_path = e2hs_writer.finish()?;

        info!("Wrote index {index} to {e2hs_path:?}");
        Ok(())
    }
}

/// Lookup the pre merge accumulator & hash for the given index.
async fn lookup_pre_merge_accumulator(
    index: u64,
    pre_merge_acc: &PreMergeAccumulator,
    portal_accumulator_path: &Path,
) -> anyhow::Result<EpochAccumulator> {
    let hash = pre_merge_acc.historical_epochs[index as usize];
    let hash_pretty = hash.to_string();
    let hash_pretty = hash_pretty.trim_start_matches("0x");
    let per_merge_accumulator_path = format!(
        "{}/bridge_content/0x03{hash_pretty}.portalcontent",
        portal_accumulator_path.display(),
    );
    let pre_merge_accumulator = match fs::read(&per_merge_accumulator_path) {
        Ok(val) => EpochAccumulator::from_ssz_bytes(&val).map_err(|err| anyhow!("{err:?}"))?,
        Err(_) => {
            return Err(anyhow!(
                "Unable to find local per merge accumulator at path: {per_merge_accumulator_path:?}"
            ))
        }
    };
    Ok(pre_merge_accumulator)
}
