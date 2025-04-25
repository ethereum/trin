use std::{cmp::max, collections::HashMap, path::PathBuf, sync::Arc};

use alloy::{
    consensus::BlockBody as AlloyBlockBody,
    eips::eip4895::{Withdrawal, Withdrawals},
    primitives::B256,
};
use anyhow::{anyhow, bail, ensure};
use ethportal_api::types::execution::{
    accumulator::EpochAccumulator,
    block_body::BlockBody,
    header_with_proof::{
        build_capella_historical_summaries_proof, build_historical_roots_proof, BlockHeaderProof,
        BlockProofHistoricalHashesAccumulator, HeaderWithProof,
    },
    receipts::Receipts,
};
use portal_bridge::api::execution::ExecutionApi;
use tokio::try_join;
use trin_execution::era::beacon::decode_transactions;
use trin_validation::{
    accumulator::PreMergeAccumulator,
    constants::{CANCUN_BLOCK_NUMBER, EPOCH_SIZE, MERGE_BLOCK_NUMBER, SHANGHAI_BLOCK_NUMBER},
    header_validator::HeaderValidator,
};
use url::Url;

use crate::{
    provider::EraProvider,
    utils::{
        lookup_epoch_acc, pre_capella_execution_payload_to_header,
        pre_deneb_execution_payload_to_header,
    },
};

pub struct AllBlockData {
    pub block_number: u64,
    pub header_with_proof: HeaderWithProof,
    pub body: BlockBody,
    pub receipts: Receipts,
}

// This struct reads all blocks in an epoch and creates the block data
// along with the corresponding proofs required to create an E2HS file.
pub struct EpochReader {
    starting_block: u64,
    ending_block: u64,
    epoch_accumulator: Option<Arc<EpochAccumulator>>,
    era_provider: EraProvider,
    receipts: HashMap<u64, Receipts>,
}

impl EpochReader {
    pub async fn new(
        epoch_index: u64,
        epoch_acc_path: PathBuf,
        el_provider_url: Url,
    ) -> anyhow::Result<Self> {
        let execution_api = ExecutionApi::new(el_provider_url.clone(), el_provider_url, 10).await?;
        let latest_block = execution_api.get_latest_block_number().await?;
        let maximum_epoch = latest_block / EPOCH_SIZE;
        ensure!(
            epoch_index <= maximum_epoch,
            "Epoch {epoch_index} is greater than the maximum epoch {maximum_epoch}"
        );

        let starting_block = epoch_index * EPOCH_SIZE;
        let epoch_accumulator = match starting_block < MERGE_BLOCK_NUMBER {
            true => {
                let header_validator = HeaderValidator::new();
                Some(Arc::new(
                    lookup_epoch_acc(
                        epoch_index,
                        &header_validator.pre_merge_acc,
                        &epoch_acc_path,
                    )
                    .await?,
                ))
            }
            false => None,
        };

        let ending_block = starting_block + EPOCH_SIZE;
        let receipts_handle = tokio::spawn(async move {
            if ending_block >= MERGE_BLOCK_NUMBER {
                execution_api
                    .get_receipts(max(MERGE_BLOCK_NUMBER, starting_block)..ending_block)
                    .await
            } else {
                Ok(HashMap::new())
            }
        });
        let era_provider_handle = tokio::spawn(async move { EraProvider::new(epoch_index).await });
        let (receipts_result, era_provider_result) =
            try_join!(receipts_handle, era_provider_handle)?;
        let receipts = receipts_result?;
        let era_provider = era_provider_result?;

        Ok(Self {
            starting_block,
            ending_block,
            epoch_accumulator,
            receipts,
            era_provider,
        })
    }

    fn get_pre_merge_block_data(&self, block_number: u64) -> anyhow::Result<AllBlockData> {
        let tuple = self.era_provider.get_pre_merge(block_number)?;
        let header = tuple.header.header;
        let Some(epoch_acc) = &self.epoch_accumulator else {
            bail!("Epoch accumulator not found for pre-merge block: {block_number}")
        };
        let proof = PreMergeAccumulator::construct_proof(&header, epoch_acc)?;
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

    fn get_merge_to_capella_block_data(
        &mut self,
        block_number: u64,
    ) -> anyhow::Result<AllBlockData> {
        let (block, era) = self.era_provider.get_post_merge(block_number)?;
        let block = block
            .block
            .message_merge()
            .map_err(|e| anyhow!("Unable to decode merge block: {e:?}"))?;
        let execution_payload = &block.body.execution_payload;
        let transactions = decode_transactions(&execution_payload.transactions)?;

        let header_with_proof = HeaderWithProof {
            header: pre_capella_execution_payload_to_header(execution_payload, &transactions)?,
            proof: BlockHeaderProof::HistoricalRoots(build_historical_roots_proof(
                block.slot,
                &era.historical_batch,
                block,
            )),
        };
        let body = BlockBody(AlloyBlockBody {
            transactions,
            ommers: vec![],
            withdrawals: None,
        });
        let receipts = self.get_receipts(block_number, header_with_proof.header.receipts_root)?;
        Ok(AllBlockData {
            block_number,
            header_with_proof,
            body,
            receipts,
        })
    }

    fn get_capella_to_deneb_block_data(
        &mut self,
        block_number: u64,
    ) -> anyhow::Result<AllBlockData> {
        let (block, era) = self.era_provider.get_post_merge(block_number)?;
        let block = block
            .block
            .message_capella()
            .map_err(|e| anyhow!("Unable to decode capella block: {e:?}"))?;
        let payload = &block.body.execution_payload;
        let transactions = decode_transactions(&payload.transactions)?;
        let withdrawals: Vec<Withdrawal> =
            payload.withdrawals.iter().map(Withdrawal::from).collect();

        let header_with_proof = HeaderWithProof {
            header: pre_deneb_execution_payload_to_header(payload, &transactions, &withdrawals)?,
            proof: BlockHeaderProof::HistoricalSummariesCapella(
                build_capella_historical_summaries_proof(
                    block.slot,
                    &era.historical_batch.block_roots,
                    block,
                ),
            ),
        };
        let body = BlockBody(AlloyBlockBody {
            transactions,
            ommers: vec![],
            withdrawals: Some(Withdrawals::new(withdrawals)),
        });
        let receipts = self.get_receipts(block_number, header_with_proof.header.receipts_root)?;
        Ok(AllBlockData {
            block_number,
            header_with_proof,
            body,
            receipts,
        })
    }

    pub fn iter_blocks(mut self) -> impl Iterator<Item = anyhow::Result<AllBlockData>> {
        (self.starting_block..self.ending_block).map(move |current_block| {
            if current_block < MERGE_BLOCK_NUMBER {
                self.get_pre_merge_block_data(current_block)
            } else if current_block < SHANGHAI_BLOCK_NUMBER {
                self.get_merge_to_capella_block_data(current_block)
            } else if current_block < CANCUN_BLOCK_NUMBER {
                self.get_capella_to_deneb_block_data(current_block)
            } else {
                Err(anyhow!("Unsupported block number: {current_block}"))
            }
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
