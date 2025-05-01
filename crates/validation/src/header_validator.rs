use alloy::{consensus::Header, primitives::B256};
use alloy_hardforks::EthereumHardforks;
use anyhow::{anyhow, bail};
use ethportal_api::{
    consensus::historical_summaries::HistoricalSummaries,
    types::{
        execution::header_with_proof::{
            BeaconBlockProofHistoricalRoots, BeaconBlockProofHistoricalSummaries, BlockHeaderProof,
            BlockProofHistoricalHashesAccumulator, BlockProofHistoricalRoots,
            BlockProofHistoricalSummariesCapella, BlockProofHistoricalSummariesDeneb,
            HeaderWithProof,
        },
        network_spec::network_spec,
    },
};

use crate::{
    accumulator::PreMergeAccumulator,
    constants::{CAPELLA_FORK_EPOCH, EPOCH_SIZE, SLOTS_PER_EPOCH},
    historical_roots_acc::HistoricalRootsAccumulator,
    merkle::proof::verify_merkle_proof,
};

/// HeaderValidator is responsible for validating pre-merge and post-merge headers with their
/// respective proofs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HeaderValidator {
    /// Pre-merge accumulator used to validate pre-merge headers.
    pub pre_merge_acc: PreMergeAccumulator,
    /// Historical roots accumulator used to validate post-merge/pre-Capella headers.
    pub historical_roots_acc: HistoricalRootsAccumulator,
}

impl HeaderValidator {
    pub fn new() -> Self {
        let pre_merge_acc = PreMergeAccumulator::default();
        let historical_roots_acc = HistoricalRootsAccumulator::default();

        Self {
            pre_merge_acc,
            historical_roots_acc,
        }
    }

    pub fn validate_header_with_proof(
        &self,
        header_with_proof: &HeaderWithProof,
    ) -> anyhow::Result<()> {
        let HeaderWithProof { header, proof } = header_with_proof;
        match proof {
            BlockHeaderProof::HistoricalHashes(proof) => {
                self.verify_pre_merge_header(header, proof)
            }
            BlockHeaderProof::HistoricalRoots(proof) => self.verify_merge_to_capella_header(
                header.number,
                header.timestamp,
                header.hash_slow(),
                proof,
            ),
            BlockHeaderProof::HistoricalSummariesCapella(_) => Err(anyhow!(
                "HistoricalSummariesCapella header validation is not implemented yet."
            )),
            BlockHeaderProof::HistoricalSummariesDeneb(_) => Err(anyhow!(
                "HistoricalSummariesDeneb header validation is not implemented yet."
            )),
        }
    }

    fn verify_pre_merge_header(
        &self,
        header: &Header,
        proof: &BlockProofHistoricalHashesAccumulator,
    ) -> anyhow::Result<()> {
        if network_spec().is_paris_active_at_block(header.number) {
            bail!("Invalid proof type found for post-merge header.");
        }

        // Calculate generalized index for header
        // https://github.com/ethereum/consensus-specs/blob/v0.11.1/ssz/merkle-proofs.md#generalized-merkle-tree-index
        let header_index = header.number % EPOCH_SIZE;
        let gen_index = (EPOCH_SIZE * 2 * 2) + (header_index * 2);

        // Look up historical epoch hash for header from pre-merge accumulator
        let epoch_index = self.pre_merge_acc.get_epoch_index_of_header(header) as usize;
        let epoch_hash = self.pre_merge_acc.historical_epochs[epoch_index];

        if !verify_merkle_proof(
            header.hash_slow(),
            proof,
            15,
            gen_index as usize,
            epoch_hash,
        ) {
            bail!("Execution block proof verification failed for pre-Merge header");
        }
        Ok(())
    }

    /// A method to verify the chain of proofs for post-merge/pre-Capella execution headers.
    fn verify_merge_to_capella_header(
        &self,
        block_number: u64,
        block_timestamp: u64,
        header_hash: B256,
        proof: &BlockProofHistoricalRoots,
    ) -> anyhow::Result<()> {
        if !network_spec().is_paris_active_at_block(block_number) {
            bail!("Invalid BlockProofHistoricalRoots found for pre-Merge header.");
        }
        if network_spec().is_shanghai_active_at_timestamp(block_timestamp) {
            bail!("Invalid BlockProofHistoricalRoots found for post-Shanghai header.");
        }

        // Verify the chain of proofs for execution block header inclusion in beacon block
        if !self.verify_bellatrix_to_deneb_execution_block_proof(
            header_hash,
            &proof.execution_block_proof,
            proof.beacon_block_root,
        ) {
            bail!("Execution block proof verification failed for Merge-Capella header");
        }

        // Verify beacon block inclusion in historical roots
        if !self.verify_historical_roots_beacon_block_proof(
            proof.slot,
            proof.beacon_block_root,
            &proof.beacon_block_proof,
        ) {
            bail!("Beacon block proof verification failed for Merge-Capella header");
        }

        Ok(())
    }

    /// A method to verify the chain of proofs for post-Capella/pre-Deneb execution headers.
    #[allow(dead_code)] // TODO: Remove this when used
    fn verify_capella_to_deneb_header(
        &self,
        block_timestamp: u64,
        header_hash: B256,
        proof: &BlockProofHistoricalSummariesCapella,
        historical_summaries: &HistoricalSummaries,
    ) -> anyhow::Result<()> {
        if !network_spec().is_shanghai_active_at_timestamp(block_timestamp) {
            bail!("Invalid BlockProofHistoricalSummariesCapella found for pre-Shanghai header.");
        }
        if network_spec().is_cancun_active_at_timestamp(block_timestamp) {
            bail!("Invalid BlockProofHistoricalSummariesCapella found for post-Cancun header.");
        }

        // Verify the chain of proofs for execution block header inclusion in beacon block
        if !self.verify_bellatrix_to_deneb_execution_block_proof(
            header_hash,
            &proof.execution_block_proof,
            proof.beacon_block_root,
        ) {
            bail!("Execution block proof verification failed for Capella-Deneb header");
        }

        // Verify beacon block inclusion in historical summaries
        if !self.verify_historical_summaries_beacon_block_proof(
            proof.slot,
            proof.beacon_block_root,
            &proof.beacon_block_proof,
            historical_summaries,
        ) {
            bail!("Beacon block proof verification failed for Capella-Deneb header");
        }

        Ok(())
    }

    /// A method to verify the chain of proofs for post-Deneb execution headers.
    #[allow(dead_code)] // TODO: Remove this when used
    fn verify_post_deneb_header(
        &self,
        block_timestamp: u64,
        header_hash: B256,
        proof: &BlockProofHistoricalSummariesDeneb,
        historical_summaries: &HistoricalSummaries,
    ) -> anyhow::Result<()> {
        if !network_spec().is_cancun_active_at_timestamp(block_timestamp) {
            bail!("Invalid BlockProofHistoricalSummariesDeneb found for pre-Cancun header.");
        }

        // Verify the chain of proofs for execution block header inclusion in beacon block
        if !self.verify_post_deneb_execution_block_proof(
            header_hash,
            &proof.execution_block_proof,
            proof.beacon_block_root,
        ) {
            bail!("Execution block proof verification failed for post-Deneb header");
        }

        // Verify beacon block inclusion in historical summaries
        if !self.verify_historical_summaries_beacon_block_proof(
            proof.slot,
            proof.beacon_block_root,
            &proof.beacon_block_proof,
            historical_summaries,
        ) {
            bail!("Beacon block proof verification failed for post-Deneb header");
        }

        Ok(())
    }

    /// Verify that the execution block header is included in Bellatrix/Capella beacon block
    #[must_use]
    fn verify_bellatrix_to_deneb_execution_block_proof(
        &self,
        execution_header_hash: B256,
        execution_block_proof: &[B256],
        block_body_root: B256,
    ) -> bool {
        // BeaconBlock level:
        // - 8 as there are 5 fields
        // - 4 as index (pos) of field is 4
        // let gen_index_top_level = (1 * 8 + 4) = 12
        // BeaconBlockBody level:
        // - 16 as there are 10 (Bellatrix) or 11 (Capella) fields
        // - 9 as index (pos) of field is 9
        // let gen_index_mid_level = (gen_index_top_level * 16 + 9) = 201
        // ExecutionPayload level:
        // - 16 as there are 14 (Bellatrix) or 15 (Capella) fields
        // - 12 as pos of field is 12
        // let gen_index = (gen_index_mid_level * 16 + 12) = 3228
        let gen_index = 3228;

        verify_merkle_proof(
            execution_header_hash,
            execution_block_proof,
            execution_block_proof.len(),
            gen_index,
            block_body_root,
        )
    }

    /// Verify that the execution block header is included in Deneb/Electra beacon block
    #[must_use]
    fn verify_post_deneb_execution_block_proof(
        &self,
        execution_header_hash: B256,
        execution_block_proof: &[B256],
        block_body_root: B256,
    ) -> bool {
        // BeaconBlock level:
        // - 8 as there are 5 fields
        // - 4 as index (pos) of field is 4
        // let gen_index_top_level = (1 * 8 + 4) = 12
        // BeaconBlockBody level:
        // - 16 as there are 12 fields
        // - 9 as index (pos) of field is 9
        // let gen_index_mid_level = (gen_index_top_level * 16 + 9) = 201
        // ExecutionPayload level:
        // - 32 as there are 17 fields
        // - 12 as pos of field is 12
        // let gen_index = (gen_index_mid_level * 32 + 12) = 6444
        let gen_index = 6444;

        verify_merkle_proof(
            execution_header_hash,
            execution_block_proof,
            execution_block_proof.len(),
            gen_index,
            block_body_root,
        )
    }

    /// Verifies that pre-Capella Beacon Block root is included in the `HistoricalRoots`.
    #[must_use]
    fn verify_historical_roots_beacon_block_proof(
        &self,
        slot: u64,
        beacon_block_root: B256,
        beacon_block_proof: &BeaconBlockProofHistoricalRoots,
    ) -> bool {
        let block_root_index = slot % EPOCH_SIZE;
        let gen_index = 2 * EPOCH_SIZE + block_root_index;
        let historical_root_index = slot / EPOCH_SIZE;
        let historical_root =
            self.historical_roots_acc.historical_roots[historical_root_index as usize];

        verify_merkle_proof(
            beacon_block_root,
            beacon_block_proof,
            14,
            gen_index as usize,
            historical_root,
        )
    }

    /// Verifies that post-Capella Beacon Block root is included in the [HistoricalSummaries].
    #[must_use]
    fn verify_historical_summaries_beacon_block_proof(
        &self,
        slot: u64,
        beacon_block_root: B256,
        beacon_block_proof: &BeaconBlockProofHistoricalSummaries,
        historical_summaries: &HistoricalSummaries,
    ) -> bool {
        let block_root_index = slot % EPOCH_SIZE;
        let gen_index = EPOCH_SIZE + block_root_index;
        let historical_summary_index = (slot - CAPELLA_FORK_EPOCH * SLOTS_PER_EPOCH) / EPOCH_SIZE;
        let historical_summary = &historical_summaries[historical_summary_index as usize];

        verify_merkle_proof(
            beacon_block_root,
            beacon_block_proof,
            13,
            gen_index as usize,
            historical_summary.block_summary_root,
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use std::{collections::HashMap, path::PathBuf, str::FromStr};

    use alloy::primitives::{Address, B256};
    use alloy_hardforks::EthereumHardfork;
    use ethportal_api::{
        types::execution::header_with_proof::{BlockHeaderProof, HeaderWithProof},
        HistoryContentKey,
    };
    use rstest::*;
    use serde::Deserialize;
    use ssz::Decode;
    use tree_hash::TreeHash;
    use trin_utils::{
        submodules::{
            read_json_portal_spec_tests_file, read_ssz_portal_spec_tests_file,
            read_yaml_portal_spec_tests_file,
        },
        testing::ContentItem,
    };

    use super::*;
    use crate::constants::DEFAULT_PRE_MERGE_ACC_HASH;

    const SPEC_TESTS_DIR: &str = "tests/mainnet/history";

    mod pre_merge {
        use super::*;

        #[rstest]
        fn verify_header(
            #[values(
                1_000_001, 1_000_002, 1_000_003, 1_000_004, 1_000_005, 1_000_006, 1_000_007,
                1_000_008, 1_000_009, 1_000_010
            )]
            block_number: u64,
        ) {
            let test_data: HashMap<u64, ContentItem<HistoryContentKey>> =
                read_json_portal_spec_tests_file(
                    "tests/mainnet/history/headers_with_proof/1000001-1000010.json",
                )
                .unwrap();

            let header_with_proof =
                HeaderWithProof::from_ssz_bytes(&test_data[&block_number].raw_content_value)
                    .unwrap();

            get_mainnet_header_validator()
                .validate_header_with_proof(&header_with_proof)
                .unwrap();
        }

        #[rstest]
        fn verify_header_from_partial_epoch(#[values(15_537_392, 15_537_393)] block_number: u64) {
            let test_data: ContentItem<HistoryContentKey> = read_yaml_portal_spec_tests_file(
                format!("tests/mainnet/history/headers_with_proof/{block_number}.yaml"),
            )
            .unwrap();

            let header_with_proof =
                HeaderWithProof::from_ssz_bytes(&test_data.raw_content_value).unwrap();

            get_mainnet_header_validator()
                .validate_header_with_proof(&header_with_proof)
                .unwrap();
        }

        #[test]
        #[should_panic = "Execution block proof verification failed for pre-Merge header"]
        fn invalidate_invalid_proofs() {
            let test_data: ContentItem<HistoryContentKey> = read_yaml_portal_spec_tests_file(
                "tests/mainnet/history/headers_with_proof/1000010.yaml",
            )
            .unwrap();
            let mut header_with_proof =
                HeaderWithProof::from_ssz_bytes(&test_data.raw_content_value).unwrap();

            // Change order of hashes in the proof to make it invalid
            let BlockHeaderProof::HistoricalHashes(proof) = &mut header_with_proof.proof else {
                panic!("Expected HistoricalHashes proof");
            };
            proof.swap(0, 1);

            get_mainnet_header_validator()
                .validate_header_with_proof(&header_with_proof)
                .unwrap()
        }

        #[test]
        #[should_panic = "Invalid proof type found for post-merge header."]
        fn header_validator_invalidates_post_merge_header_with_accumulator_proof() {
            let header_validator = get_mainnet_header_validator();
            let future_height = EthereumHardfork::Paris.mainnet_activation_block().unwrap();
            let future_header = generate_random_header(&future_height);
            let future_header_with_proof = HeaderWithProof {
                header: future_header,
                proof: BlockHeaderProof::HistoricalHashes(Default::default()),
            };
            header_validator
                .validate_header_with_proof(&future_header_with_proof)
                .unwrap();
        }
    }

    mod merge_to_capella {
        use super::*;

        #[rstest]
        fn verify_header(
            #[values(15_537_394, 15_539_558, 15_547_621, 15_555_729, 17_034_869)] block_number: u64,
        ) {
            let header_validator = get_mainnet_header_validator();

            let BlockHashWithProof::<BlockProofHistoricalRoots> { header_hash, proof } =
                read_yaml_portal_spec_tests_file(
                    PathBuf::from(SPEC_TESTS_DIR)
                        .join(format!("headers_with_proof/block_proofs_bellatrix/beacon_block_proof-{block_number}.yaml")),
                )
                .unwrap();

            header_validator
                .verify_merge_to_capella_header(
                    block_number,
                    network_spec().slot_to_timestamp(proof.slot),
                    header_hash,
                    &proof,
                )
                .unwrap();
        }

        #[test]
        #[should_panic = "Invalid BlockProofHistoricalRoots found for pre-Merge header"]
        fn pre_merge_block() {
            let dummy_proof = BlockProofHistoricalRoots {
                beacon_block_proof: Default::default(),
                beacon_block_root: Default::default(),
                execution_block_proof: Default::default(),
                slot: Default::default(),
            };
            get_mainnet_header_validator()
                .verify_merge_to_capella_header(
                    EthereumHardfork::Paris.mainnet_activation_block().unwrap() - 1,
                    EthereumHardfork::Paris
                        .mainnet_activation_timestamp()
                        .unwrap()
                        - 1,
                    B256::random(),
                    &dummy_proof,
                )
                .unwrap()
        }

        #[test]
        #[should_panic = "Invalid BlockProofHistoricalRoots found for post-Shanghai header"]
        fn post_capella_block() {
            let dummy_proof = BlockProofHistoricalRoots {
                beacon_block_proof: Default::default(),
                beacon_block_root: Default::default(),
                execution_block_proof: Default::default(),
                slot: Default::default(),
            };
            get_mainnet_header_validator()
                .verify_merge_to_capella_header(
                    EthereumHardfork::Shanghai
                        .mainnet_activation_block()
                        .unwrap(),
                    EthereumHardfork::Shanghai
                        .mainnet_activation_timestamp()
                        .unwrap(),
                    B256::random(),
                    &dummy_proof,
                )
                .unwrap()
        }
    }

    mod capella_to_deneb {
        use super::*;

        #[rstest]
        fn verify_header(
            #[values(17_034_870, 17_042_287, 17_062_257, 19_426_586)] block_number: u64,
        ) {
            let header_validator = get_mainnet_header_validator();

            let BlockHashWithProof::<BlockProofHistoricalSummariesCapella> { header_hash, proof } =
                read_yaml_portal_spec_tests_file(PathBuf::from(SPEC_TESTS_DIR).join(format!(
                "headers_with_proof/block_proofs_capella/beacon_block_proof-{block_number}.yaml"
            )))
                .unwrap();

            let historical_summaries = read_historical_summaries();

            header_validator
                .verify_capella_to_deneb_header(
                    network_spec().slot_to_timestamp(proof.slot),
                    header_hash,
                    &proof,
                    &historical_summaries,
                )
                .unwrap();
        }

        #[test]
        #[should_panic = "Invalid BlockProofHistoricalSummariesCapella found for pre-Shanghai header"]
        fn pre_capella_block() {
            let dummy_proof = BlockProofHistoricalSummariesCapella {
                beacon_block_proof: Default::default(),
                beacon_block_root: Default::default(),
                execution_block_proof: Default::default(),
                slot: Default::default(),
            };
            get_mainnet_header_validator()
                .verify_capella_to_deneb_header(
                    EthereumHardfork::Shanghai
                        .mainnet_activation_timestamp()
                        .unwrap()
                        - 1,
                    B256::random(),
                    &dummy_proof,
                    &read_historical_summaries(),
                )
                .unwrap()
        }

        #[test]
        #[should_panic = "Invalid BlockProofHistoricalSummariesCapella found for post-Cancun header"]
        fn post_deneb_block() {
            let dummy_proof = BlockProofHistoricalSummariesCapella {
                beacon_block_proof: Default::default(),
                beacon_block_root: Default::default(),
                execution_block_proof: Default::default(),
                slot: Default::default(),
            };
            get_mainnet_header_validator()
                .verify_capella_to_deneb_header(
                    EthereumHardfork::Cancun
                        .mainnet_activation_timestamp()
                        .unwrap(),
                    B256::random(),
                    &dummy_proof,
                    &read_historical_summaries(),
                )
                .unwrap()
        }
    }

    mod post_deneb {
        use super::*;

        #[rstest]
        fn verify_header(#[values(19_426_587, 22_162_263)] block_number: u64) {
            let header_validator = get_mainnet_header_validator();

            let BlockHashWithProof::<BlockProofHistoricalSummariesDeneb> { header_hash, proof } =
                read_yaml_portal_spec_tests_file(PathBuf::from(SPEC_TESTS_DIR).join(format!(
                    "headers_with_proof/block_proofs_deneb/beacon_block_proof-{block_number}.yaml"
                )))
                .unwrap();

            let historical_summaries = read_historical_summaries();

            header_validator
                .verify_post_deneb_header(
                    network_spec().slot_to_timestamp(proof.slot),
                    header_hash,
                    &proof,
                    &historical_summaries,
                )
                .unwrap();
        }

        #[test]
        #[should_panic = "Invalid BlockProofHistoricalSummariesDeneb found for pre-Cancun header"]
        fn pre_deneb_block() {
            let dummy_proof = BlockProofHistoricalSummariesDeneb {
                beacon_block_proof: Default::default(),
                beacon_block_root: Default::default(),
                execution_block_proof: Default::default(),
                slot: Default::default(),
            };
            get_mainnet_header_validator()
                .verify_post_deneb_header(
                    EthereumHardfork::Cancun
                        .mainnet_activation_timestamp()
                        .unwrap()
                        - 1,
                    B256::random(),
                    &dummy_proof,
                    &read_historical_summaries(),
                )
                .unwrap()
        }
    }

    //
    // Testing utils
    //

    #[derive(Deserialize)]
    struct BlockHashWithProof<T> {
        #[serde(rename = "execution_block_header")]
        header_hash: B256,
        #[serde(flatten)]
        proof: T,
    }

    fn get_mainnet_header_validator() -> HeaderValidator {
        let header_validator = HeaderValidator::default();
        assert_eq!(
            header_validator.pre_merge_acc.tree_hash_root(),
            B256::from_str(DEFAULT_PRE_MERGE_ACC_HASH).unwrap()
        );
        header_validator
    }

    fn generate_random_header(height: &u64) -> Header {
        Header {
            parent_hash: B256::random(),
            ommers_hash: B256::random(),
            beneficiary: Address::random(),
            state_root: B256::random(),
            transactions_root: B256::random(),
            receipts_root: B256::random(),
            number: *height,
            timestamp: 1,
            ..Default::default()
        }
    }

    fn read_historical_summaries() -> HistoricalSummaries {
        read_ssz_portal_spec_tests_file(
            PathBuf::from(SPEC_TESTS_DIR)
                .join("headers_with_proof/beacon_data/historical_summaries_at_slot_11476992.ssz"),
        )
        .unwrap()
    }
}
