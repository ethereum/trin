use std::{path::PathBuf, sync::Arc};

use alloy::{
    consensus::BlockBody as AlloyBlockBody,
    eips::eip4895::{Withdrawal, Withdrawals},
    primitives::B256,
};
use anyhow::{anyhow, bail, ensure};
use async_stream::stream;
use e2store::era1::Era1;
use ethportal_api::types::{
    consensus::beacon_state::HistoricalBatch,
    execution::{
        accumulator::EpochAccumulator,
        block_body::BlockBody,
        header_with_proof::{
            BlockHeaderProof, BlockProofHistoricalHashesAccumulator, BlockProofHistoricalRoots,
            BlockProofHistoricalSummaries, HeaderWithProof,
        },
        receipts::Receipts,
    },
};
use futures::Stream;
use portal_bridge::{api::execution::ExecutionApi, bridge::utils::lookup_epoch_acc};
use ssz_types::{typenum, FixedVector, VariableList};
use tree_hash::TreeHash;
use trin_execution::era::beacon::decode_transactions;
use trin_validation::{
    accumulator::PreMergeAccumulator,
    constants::{CANCUN_BLOCK_NUMBER, EPOCH_SIZE, MERGE_BLOCK_NUMBER, SHANGHAI_BLOCK_NUMBER},
    header_validator::HeaderValidator,
};
use url::Url;

use crate::{
    provider::EraProvider,
    utils::{pre_capella_execution_payload_to_header, pre_deneb_execution_payload_to_header},
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
    execution_api: ExecutionApi,
    era_provider: EraProvider,
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
        Ok(Self {
            starting_block,
            ending_block: starting_block + EPOCH_SIZE,
            epoch_accumulator,
            execution_api,
            era_provider: EraProvider::new(epoch_index).await?,
        })
    }

    fn get_pre_merge_block_data(&self, block_number: u64) -> anyhow::Result<AllBlockData> {
        let raw_era1 = self.era_provider.get_era1_for_block(block_number)?;
        let block_index = block_number % EPOCH_SIZE;
        let tuple = Era1::get_tuple_by_index(&raw_era1, block_index);
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

    async fn get_pre_capella_block_data(&self, block_number: u64) -> anyhow::Result<AllBlockData> {
        let era = self.era_provider.get_era_for_block(block_number)?;
        let block = era
            .blocks
            .iter()
            .find(|block| block.block.execution_block_number() == block_number)
            .ok_or_else(|| {
                anyhow!("Era file for block #{block_number} not found during pre-capella lookup")
            })?;
        let block = block
            .block
            .message_merge()
            .map_err(|e| anyhow!("Unable to decode merge block: {e:?}"))?;
        let payload = block.body.execution_payload.clone();
        let transactions = decode_transactions(&payload.transactions)?;
        let header = pre_capella_execution_payload_to_header(payload.clone(), &transactions)?;
        let historical_batch = HistoricalBatch {
            state_roots: era.era_state.state.state_roots().clone(),
            block_roots: era.era_state.state.block_roots().clone(),
        };
        let slot = block.slot;

        // create beacon block proof
        let historical_batch_proof = historical_batch.build_block_root_proof(slot % EPOCH_SIZE);
        let beacon_block_proof: FixedVector<B256, typenum::U14> = historical_batch_proof.into();

        // create execution block proof
        let mut execution_block_hash_proof = block.body.build_execution_block_hash_proof();
        let body_root_proof = block.build_body_root_proof();
        execution_block_hash_proof.extend(body_root_proof);
        let execution_block_proof: FixedVector<B256, typenum::U11> =
            execution_block_hash_proof.into();

        let proof = BlockProofHistoricalRoots {
            beacon_block_proof,
            beacon_block_root: block.tree_hash_root(),
            slot,
            execution_block_proof,
        };

        let header_with_proof = HeaderWithProof {
            header,
            proof: BlockHeaderProof::HistoricalRoots(proof),
        };
        let body = BlockBody(AlloyBlockBody {
            transactions,
            ommers: vec![],
            withdrawals: None,
        });
        let receipts = self
            .execution_api
            .get_receipts(
                block_number,
                payload.transactions.len(),
                payload.receipts_root,
            )
            .await?;
        Ok(AllBlockData {
            block_number,
            header_with_proof,
            body,
            receipts,
        })
    }

    async fn get_pre_deneb_block_data(&self, block_number: u64) -> anyhow::Result<AllBlockData> {
        let era = self.era_provider.get_era_for_block(block_number)?;
        let block = era
            .blocks
            .iter()
            .find(|block| block.block.execution_block_number() == block_number)
            .ok_or_else(|| {
                anyhow!("Era file for block #{block_number} not found during pre-deneb lookup")
            })?;
        let block = block
            .block
            .message_capella()
            .map_err(|e| anyhow!("Unable to decode capella block: {e:?}"))?;
        let payload = block.body.execution_payload.clone();
        let transactions = decode_transactions(&payload.transactions)?;
        let withdrawals: Vec<Withdrawal> =
            payload.withdrawals.iter().map(Withdrawal::from).collect();
        let header =
            pre_deneb_execution_payload_to_header(payload.clone(), &transactions, &withdrawals)?;

        let historical_batch = HistoricalBatch {
            state_roots: era.era_state.state.state_roots().clone(),
            block_roots: era.era_state.state.block_roots().clone(),
        };
        let slot = block.slot;

        // create beacon block proof
        let historical_batch_proof = historical_batch.build_block_root_proof(slot % EPOCH_SIZE);
        let beacon_block_proof: FixedVector<B256, typenum::U13> = historical_batch_proof.into();

        // create execution block proof
        let mut execution_block_hash_proof = block.body.build_execution_block_hash_proof();
        let body_root_proof = block.build_body_root_proof();
        execution_block_hash_proof.extend(body_root_proof);
        let execution_block_proof: VariableList<B256, typenum::U12> =
            execution_block_hash_proof.into();
        let proof = BlockProofHistoricalSummaries {
            beacon_block_proof,
            beacon_block_root: block.tree_hash_root(),
            slot,
            execution_block_proof,
        };

        let header_with_proof = HeaderWithProof {
            header,
            proof: BlockHeaderProof::HistoricalSummaries(proof),
        };
        let body = BlockBody(AlloyBlockBody {
            transactions,
            ommers: vec![],
            withdrawals: Some(Withdrawals::new(withdrawals)),
        });
        let receipts = self
            .execution_api
            .get_receipts(
                block_number,
                payload.transactions.len(),
                payload.receipts_root,
            )
            .await?;
        Ok(AllBlockData {
            block_number,
            header_with_proof,
            body,
            receipts,
        })
    }

    pub fn iter_blocks(self) -> impl Stream<Item = anyhow::Result<AllBlockData>> {
        stream! {
            for current_block in self.starting_block..self.ending_block {
                if current_block < MERGE_BLOCK_NUMBER {
                    yield self.get_pre_merge_block_data(current_block);
                } else if current_block < SHANGHAI_BLOCK_NUMBER {
                    yield self.get_pre_capella_block_data(current_block).await;
                } else if current_block < CANCUN_BLOCK_NUMBER {
                    yield self.get_pre_deneb_block_data(current_block).await;
                } else {
                    yield Err(anyhow!("Unsupported block number: {current_block}"));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ethportal_api::types::{
        consensus::{
            beacon_block::{BeaconBlockBellatrix, BeaconBlockCapella},
            beacon_state::BeaconState,
            fork::ForkName,
        },
        execution::header_with_proof::{
            build_historical_roots_proof, build_historical_summaries_proof,
            BlockProofHistoricalRoots, BlockProofHistoricalSummaries,
        },
    };
    use serde_yaml::Value;
    use ssz::Decode;

    use super::*;

    #[rstest::rstest]
    // epoch #575
    #[case(15539558, 4702208, "block_proofs_bellatrix/beacon_block_proof-15539558-cdf9ed89b0c43cda17398dc4da9cfc505e5ccd19f7c39e3b43474180f1051e01.yaml")]
    // epoch #576
    #[case(15547621, 4710400, "block_proofs_bellatrix/beacon_block_proof-15547621-96a9313cd506e32893d46c82358569ad242bb32786bd5487833e0f77767aec2a.yaml")]
    // epoch #577
    #[case(15555729, 4718592, "block_proofs_bellatrix/beacon_block_proof-15555729-c6fd396d54f61c6d0f1dd3653f81267b0378e9a0d638a229b24586d8fd0bc499.yaml")]
    #[tokio::test]
    async fn test_pre_capella_proof_generation(
        #[case] block_number: u64,
        #[case] slot: u64,
        #[case] file_path: &str,
    ) {
        let test_vector = std::fs::read_to_string(format!(
            "../../portal-spec-tests/tests/mainnet/history/headers_with_proof/{file_path}"
        ))
        .unwrap();
        let test_vector: Value = serde_yaml::from_str(&test_vector).unwrap();
        let actual_proof = BlockProofHistoricalRoots {
            beacon_block_proof: serde_yaml::from_value(test_vector["beacon_block_proof"].clone())
                .unwrap(),
            beacon_block_root: serde_yaml::from_value(test_vector["beacon_block_root"].clone())
                .unwrap(),
            execution_block_proof: serde_yaml::from_value(
                test_vector["execution_block_proof"].clone(),
            )
            .unwrap(),
            slot: serde_yaml::from_value(test_vector["slot"].clone()).unwrap(),
        };

        let test_assets_dir =
            format!("../../portal-spec-tests/tests/mainnet/history/headers_with_proof/beacon_data/{block_number}");
        let historical_batch_path = format!("{test_assets_dir}/historical_batch.ssz");
        let historical_batch_raw = std::fs::read(historical_batch_path).unwrap();
        let historical_batch = HistoricalBatch::from_ssz_bytes(&historical_batch_raw).unwrap();
        let block_path = format!("{test_assets_dir}/block.ssz");
        let block_raw = std::fs::read(block_path).unwrap();
        let block = BeaconBlockBellatrix::from_ssz_bytes(&block_raw).unwrap();
        let proof = build_historical_roots_proof(slot, &historical_batch, block);

        assert_eq!(actual_proof, proof);
    }

    #[rstest::rstest]
    #[case(
        17034870,
        6209538,
        // epoch #759,
        "block_proofs_capella/beacon_block_proof-17034870.yaml"
    )]
    #[case(
        17042287,
        6217730,
        // epoch #760,
        "block_proofs_capella/beacon_block_proof-17042287.yaml"
    )]
    #[case(
        17062257,
        6238210,
        // epoch #762
        "block_proofs_capella/beacon_block_proof-17062257.yaml"
    )]
    #[tokio::test]
    async fn test_pre_deneb_proof_generation(
        #[case] block_number: u64,
        #[case] slot: u64,
        #[case] file_path: &str,
    ) {
        let test_vector = std::fs::read_to_string(format!(
            "../../portal-spec-tests/tests/mainnet/history/headers_with_proof/{file_path}"
        ))
        .unwrap();
        let test_vector: Value = serde_yaml::from_str(&test_vector).unwrap();
        let actual_proof = BlockProofHistoricalSummaries {
            beacon_block_proof: serde_yaml::from_value(test_vector["beacon_block_proof"].clone())
                .unwrap(),
            beacon_block_root: serde_yaml::from_value(test_vector["beacon_block_root"].clone())
                .unwrap(),
            execution_block_proof: serde_yaml::from_value(
                test_vector["execution_block_proof"].clone(),
            )
            .unwrap(),
            slot: serde_yaml::from_value(test_vector["slot"].clone()).unwrap(),
        };

        let test_assets_dir =
            format!("../../portal-spec-tests/tests/mainnet/history/headers_with_proof/beacon_data/{block_number}");
        let state_path = format!("{test_assets_dir}/block_roots.ssz");
        let state_raw = std::fs::read(state_path).unwrap();
        let beacon_state = BeaconState::from_ssz_bytes(&state_raw, ForkName::Capella).unwrap();
        let beacon_state = beacon_state.as_capella().unwrap();
        let block_path = format!("{test_assets_dir}/block.ssz");
        let block_raw = std::fs::read(block_path).unwrap();
        let block = BeaconBlockCapella::from_ssz_bytes(&block_raw).unwrap();
        let proof = build_historical_summaries_proof(slot, beacon_state, block);

        assert_eq!(actual_proof, proof);
    }
}
