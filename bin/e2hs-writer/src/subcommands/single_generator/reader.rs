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
use e2store::{
    e2hs::{BlockTuple, HeaderWithProofEntry},
    era1::{BodyEntry, ReceiptsEntry},
};
use ethportal_api::{
    consensus::beacon_block::SignedBeaconBlock,
    types::{
        execution::{
            accumulator::EpochAccumulator,
            block_body::BlockBody,
            header_with_proof::{
                BlockHeaderProof, BlockProofHistoricalHashesAccumulator, HeaderWithProof,
            },
        },
        network_spec::network_spec,
    },
    Receipts,
};
use futures::Stream;
use portal_bridge::api::execution::ExecutionApi;
use ssz::Decode;
use tokio::try_join;
use trin_validation::{
    accumulator::PreMergeAccumulator, constants::SLOTS_PER_HISTORICAL_ROOT,
    header_validator::HeaderValidator,
};
use url::Url;

use super::provider::EraProvider;
use crate::subcommands::handle_beacon_block::{
    get_capella_to_deneb_header_and_body, get_deneb_to_electra_header_and_body,
    get_merge_to_capella_header_and_body, get_post_electra_header_and_body,
};

pub struct AllBlockData {
    pub block_number: u64,
    pub header_with_proof: HeaderWithProof,
    pub body: BlockBody,
    pub receipts: Receipts,
}

impl From<AllBlockData> for BlockTuple {
    fn from(value: AllBlockData) -> Self {
        Self {
            header_with_proof: HeaderWithProofEntry {
                header_with_proof: value.header_with_proof,
            },
            body: BodyEntry { body: value.body },
            receipts: ReceiptsEntry {
                receipts: value.receipts,
            },
        }
    }
}

// This struct reads all blocks in an period and creates the block data
// along with the corresponding proofs required to create an E2HS file.
pub struct PeriodReader {
    starting_block: u64,
    ending_block: u64,
    period_accumulator: Option<Arc<EpochAccumulator>>,
    era_provider: EraProvider,
    receipts: HashMap<u64, Receipts>,
    header_validator: HeaderValidator,
}

impl PeriodReader {
    pub async fn new(
        period_index: u64,
        period_acc_path: PathBuf,
        el_provider_url: Url,
    ) -> anyhow::Result<Self> {
        let execution_api = ExecutionApi::new(el_provider_url.clone(), el_provider_url, 10).await?;
        let latest_block = execution_api.get_latest_block_number().await?;
        let maximum_period = latest_block / SLOTS_PER_HISTORICAL_ROOT;
        ensure!(
            period_index <= maximum_period,
            "Period {period_index} is greater than the maximum period {maximum_period}"
        );

        let starting_block = period_index * SLOTS_PER_HISTORICAL_ROOT;
        let period_accumulator = if network_spec().is_paris_active_at_block(starting_block) {
            None
        } else {
            Some(Arc::new(
                lookup_period_accumulator(
                    period_index,
                    &PreMergeAccumulator::default(),
                    &period_acc_path,
                )
                .await?,
            ))
        };

        let ending_block = starting_block + SLOTS_PER_HISTORICAL_ROOT;
        let is_paris_active = network_spec().is_paris_active_at_block(ending_block);
        let receipts_handle = tokio::spawn(async move {
            if is_paris_active {
                execution_api
                    .get_receipts(starting_block..ending_block)
                    .await
            } else {
                Ok(HashMap::new())
            }
        });
        let era_provider_handle = tokio::spawn(async move { EraProvider::new(period_index).await });
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
            period_accumulator,
            receipts,
            era_provider,
            header_validator,
        })
    }

    pub fn iter_blocks(mut self) -> impl Stream<Item = anyhow::Result<AllBlockData>> {
        stream! {
            for current_block in self.starting_block..self.ending_block {
                let block = if network_spec().is_paris_active_at_block(current_block) {
                    self.get_post_merge_block_data(current_block)
                } else {
                    self.get_pre_merge_block_data(current_block)
                }?;
                self.validate_block(&block).await?;
                yield Ok(block)
            }
        }
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

    fn get_pre_merge_block_data(&self, block_number: u64) -> anyhow::Result<AllBlockData> {
        let tuple = self.era_provider.get_pre_merge(block_number)?;
        let header = tuple.header.header;
        let Some(period_acc) = &self.period_accumulator else {
            bail!("Period accumulator not found for pre-merge block: {block_number}")
        };
        let proof = PreMergeAccumulator::construct_proof(&header, period_acc)?;
        let proof = BlockProofHistoricalHashesAccumulator::new(proof.into()).map_err(|e| {
            anyhow!("Unable to convert proof to BlockProofHistoricalHashesAccumulator: {e:?}")
        })?;
        let header_with_proof = HeaderWithProof {
            header,
            proof: BlockHeaderProof::HistoricalHashes(proof),
        };
        Ok(AllBlockData {
            block_number,
            header_with_proof,
            body: tuple.body.body,
            receipts: tuple.receipts.receipts,
        })
    }

    fn get_post_merge_block_data(&mut self, block_number: u64) -> anyhow::Result<AllBlockData> {
        let (block, historical_batch) = self.era_provider.get_post_merge(block_number)?;
        ensure!(
            block.execution_block_number() == block_number,
            "Post-merge block data is for wrong block! Expected: {block_number}, actual: {}",
            block.execution_block_number()
        );

        let (header_with_proof, body) = match &block {
            SignedBeaconBlock::Bellatrix(beacon_block) => {
                get_merge_to_capella_header_and_body(&beacon_block.message, historical_batch)?
            }
            SignedBeaconBlock::Capella(beacon_block) => {
                get_capella_to_deneb_header_and_body(&beacon_block.message, historical_batch)?
            }
            SignedBeaconBlock::Deneb(beacon_block) => {
                get_deneb_to_electra_header_and_body(&beacon_block.message, historical_batch)?
            }
            SignedBeaconBlock::Electra(beacon_block) => {
                get_post_electra_header_and_body(&beacon_block.message, historical_batch)?
            }
        };

        let receipts = self.get_receipts(block_number, header_with_proof.header.receipts_root)?;

        Ok(AllBlockData {
            block_number,
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
}

/// Lookup the period accumulator & period hash for the given period index.
async fn lookup_period_accumulator(
    period_index: u64,
    pre_merge_acc: &PreMergeAccumulator,
    portal_accumulator_path: &Path,
) -> anyhow::Result<EpochAccumulator> {
    let period_hash = pre_merge_acc.historical_epochs[period_index as usize];
    let period_hash_pretty = period_hash.to_string();
    let period_hash_pretty = period_hash_pretty.trim_start_matches("0x");
    let period_acc_path = format!(
        "{}/bridge_content/0x03{period_hash_pretty}.portalcontent",
        portal_accumulator_path.display(),
    );
    let period_acc = match fs::read(&period_acc_path) {
        Ok(val) => EpochAccumulator::from_ssz_bytes(&val).map_err(|err| anyhow!("{err:?}"))?,
        Err(_) => {
            return Err(anyhow!(
                "Unable to find local period acc at path: {period_acc_path:?}"
            ))
        }
    };
    Ok(period_acc)
}
