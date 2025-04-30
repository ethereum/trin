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
        if !self.verify_bellatrix_to_deneb_execution_block_proo(
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
        if !self.verify_bellatrix_to_deneb_execution_block_proo(
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
    fn verify_bellatrix_to_deneb_execution_block_proo(
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
        let historical_summary =
            historical_summaries[historical_summary_index as usize].block_summary_root;

        verify_merkle_proof(
            beacon_block_root,
            beacon_block_proof,
            13,
            gen_index as usize,
            historical_summary,
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use std::{fs, path::PathBuf, str::FromStr};

    use alloy::{
        primitives::{Address, B256},
        rlp::Decodable,
    };
    use alloy_hardforks::EthereumHardfork;
    use ethportal_api::{
        types::execution::{
            accumulator::EpochAccumulator,
            header_with_proof::{BlockHeaderProof, HeaderWithProof},
        },
        utils::bytes::{hex_decode, hex_encode},
        HistoryContentKey, OverlayContentKey,
    };
    use rstest::*;
    use serde::Deserialize;
    use serde_json::Value;
    use ssz::{Decode, Encode};
    use tree_hash::TreeHash;
    use trin_utils::submodules::{
        read_portal_spec_tests_file, read_ssz_portal_spec_tests_file,
        read_yaml_portal_spec_tests_file,
    };

    use super::*;
    use crate::constants::DEFAULT_PRE_MERGE_ACC_HASH;

    const SPEC_TESTS_DIR: &str = "tests/mainnet/history";

    mod pre_merge {
        use super::*;

        #[rstest]
        #[case::block_number_1_000_001(1_000_001)]
        #[case::block_number_1_000_002(1_000_002)]
        #[case::block_number_1_000_003(1_000_003)]
        #[case::block_number_1_000_004(1_000_004)]
        #[case::block_number_1_000_005(1_000_005)]
        #[case::block_number_1_000_006(1_000_006)]
        #[case::block_number_1_000_007(1_000_007)]
        #[case::block_number_1_000_008(1_000_008)]
        #[case::block_number_1_000_009(1_000_009)]
        #[case::block_number_1_000_010(1_000_010)]
        #[tokio::test]
        async fn generate_and_verify_header_with_proofs(#[case] block_number: u64) {
            // Use fluffy's proofs as test data to validate that trin
            // - generates proofs which match fluffy's
            // - validates hwps

            let file = read_portal_spec_tests_file(
                "tests/mainnet/history/headers_with_proof/1000001-1000010.json",
            )
            .unwrap();
            let json: Value = serde_json::from_str(&file).unwrap();
            let hwps = json.as_object().unwrap();
            let header_validator = get_mainnet_header_validator();
            let obj = hwps.get(&block_number.to_string()).unwrap();
            // Validate content_key decodes
            let raw_ck = obj.get("content_key").unwrap().as_str().unwrap();
            let ck = HistoryContentKey::try_from_hex(raw_ck).unwrap();
            match ck {
                HistoryContentKey::BlockHeaderByHash(_) => (),
                _ => panic!("Invalid test, content key decoded improperly"),
            }
            let raw_fluffy_hwp = obj.get("content_value").unwrap().as_str().unwrap();
            let fluffy_hwp =
                HeaderWithProof::from_ssz_bytes(&hex_decode(raw_fluffy_hwp).unwrap()).unwrap();
            let header = get_header(block_number);
            let epoch_accumulator = read_epoch_accumulator_122();
            let trin_proof =
                PreMergeAccumulator::construct_proof(&header, &epoch_accumulator).unwrap();
            let fluffy_proof = match fluffy_hwp.proof {
                BlockHeaderProof::HistoricalHashes(val) => val,
                _ => panic!("test reached invalid state"),
            };
            assert_eq!(trin_proof, fluffy_proof);
            let hwp = HeaderWithProof {
                header,
                proof: BlockHeaderProof::HistoricalHashes(trin_proof),
            };
            header_validator.validate_header_with_proof(&hwp).unwrap();
        }

        #[rstest]
        #[case::block_number_15_537_392(HEADER_RLP_15_537_392, 15_537_392)]
        #[case::block_number_15_537_393(HEADER_RLP_15_537_393, 15_537_393)]
        fn generate_and_verify_header_with_proofs_from_partial_epoch(
            #[case] header_rlp: &str,
            #[case] block_number: u64,
        ) {
            let header = Header::decode(&mut hex_decode(header_rlp).unwrap().as_slice()).unwrap();
            assert_eq!(header.number, block_number);
            let epoch_acc_bytes = fs::read("./src/assets/epoch_accs/0xe6ebe562c89bc8ecb94dc9b2889a27a816ec05d3d6bd1625acad72227071e721.bin").unwrap();
            let epoch_acc = EpochAccumulator::from_ssz_bytes(&epoch_acc_bytes).unwrap();
            assert_eq!(epoch_acc.len(), 5362);
            let proof = PreMergeAccumulator::construct_proof(&header, &epoch_acc).unwrap();
            assert_eq!(proof.len(), 15);
            let header_with_proof = HeaderWithProof {
                header,
                proof: BlockHeaderProof::HistoricalHashes(proof),
            };
            HeaderValidator::new()
                .validate_header_with_proof(&header_with_proof)
                .unwrap();
            let encoded_hwp = hex_encode(header_with_proof.as_ssz_bytes());

            let hwp_test_vector = serde_yaml::from_str::<serde_yaml::Value>(
                &read_portal_spec_tests_file(format!(
                    "tests/mainnet/history/headers_with_proof/{block_number}.yaml",
                ))
                .unwrap(),
            )
            .unwrap();
            let expected_hwp = hwp_test_vector["content_value"].as_str().unwrap();
            assert_eq!(encoded_hwp, expected_hwp);
        }

        #[tokio::test]
        #[should_panic = "Execution block proof verification failed for pre-Merge header"]
        async fn invalidate_invalid_proofs() {
            let header_validator = get_mainnet_header_validator();
            let header = get_header(1_000_001);
            let epoch_accumulator = read_epoch_accumulator_122();
            let mut proof =
                PreMergeAccumulator::construct_proof(&header, &epoch_accumulator).unwrap();
            proof.swap(0, 1);
            let hwp = HeaderWithProof {
                header,
                proof: BlockHeaderProof::HistoricalHashes(proof),
            };
            header_validator.validate_header_with_proof(&hwp).unwrap()
        }

        #[tokio::test]
        #[should_panic = "Invalid proof type found for post-merge header."]
        async fn header_validator_invalidates_post_merge_header_with_accumulator_proof() {
            let header_validator = get_mainnet_header_validator();
            let future_height = EthereumHardfork::Paris.mainnet_activation_block().unwrap();
            let future_header = generate_random_header(&future_height);
            let future_hwp = HeaderWithProof {
                header: future_header,
                proof: BlockHeaderProof::HistoricalHashes(Default::default()),
            };
            header_validator
                .validate_header_with_proof(&future_hwp)
                .unwrap();
        }
    }

    mod merge_to_capella {
        use super::*;

        #[rstest]
        #[case::block_number_15_539_558(
            15_539_558,
            "beacon_block_proof-15539558-cdf9ed89b0c43cda17398dc4da9cfc505e5ccd19f7c39e3b43474180f1051e01.yaml",
        )]
        #[case::block_number_15_547_621(
            15_547_621,
            "beacon_block_proof-15547621-96a9313cd506e32893d46c82358569ad242bb32786bd5487833e0f77767aec2a.yaml",
        )]
        #[case::block_number_15_555_729(
            15_555_729,
            "beacon_block_proof-15555729-c6fd396d54f61c6d0f1dd3653f81267b0378e9a0d638a229b24586d8fd0bc499.yaml",
        )]
        #[tokio::test]
        async fn verify_header(#[case] block_number: u64, #[case] filename: &str) {
            let header_validator = get_mainnet_header_validator();

            let BlockHashWithProof::<BlockProofHistoricalRoots> { header_hash, proof } =
                read_yaml_portal_spec_tests_file(
                    PathBuf::from(SPEC_TESTS_DIR)
                        .join("headers_with_proof/block_proofs_bellatrix")
                        .join(filename),
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
        #[case::block_number_17_034_870(17_034_870)]
        #[case::block_number_17_042_287(17_042_287)]
        #[case::block_number_17_062_257(17_062_257)]
        #[tokio::test]
        async fn verify_header(#[case] block_number: u64) {
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
        #[case::block_number_22_162_263(22_162_263)]
        #[tokio::test]
        async fn verify_header(#[case] block_number: u64) {
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

    pub(crate) fn get_header(number: u64) -> Header {
        let file = fs::read_to_string("./src/assets/header_rlps.json").unwrap();
        let json: Value = serde_json::from_str(&file).unwrap();
        let json = json.as_object().unwrap();
        let raw_header = json.get(&number.to_string()).unwrap().as_str().unwrap();
        Decodable::decode(&mut hex_decode(raw_header).unwrap().as_slice()).unwrap()
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

    fn read_epoch_accumulator_122() -> EpochAccumulator {
        read_ssz_portal_spec_tests_file(
            PathBuf::from(SPEC_TESTS_DIR).join("accumulator/epoch-record-00122.ssz"),
        )
        .unwrap()
    }

    const HEADER_RLP_15_537_392: &str = "0xf90218a02f1dc309c7cc0a5a2e3b3dd9315fea0ffbc53c56f9237f3ca11b20de0232f153a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ea674fdde714fd979de3edf0f56aa9716b898ec8a0fee48a40a2765ab31fcd06ab6956341d13dc2c4b9762f2447aa425bb1c089b30a082864b3a65d1ac1917c426d48915dca0fc966fbf3f30fd051659f35dc3fd9be1a013c10513b52358022f800e2f9f1c50328798427b1b4a1ebbbd20b7417fb9719db90100ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff872741c5e4f6c39283ed14f08401c9c3808401c9a028846322c95c8f617369612d65617374322d31763932a02df332ffb74ecd15c9873d3f6153b878e1c514495dfb6e89ad88e574582b02a488232b0043952c93d98508fb17c6ee";
    const HEADER_RLP_15_537_393: &str = "0xf9021ba02b3ea3cd4befcab070812443affb08bf17a91ce382c714a536ca3cacab82278ba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794829bd824b016326a401d083b33d092293333a830a04919dafa6ac8becfbbd0c2808f6c9511a057c21e42839caff5dfb6d3ef514951a0dd5eec02b019ff76e359b09bfa19395a2a0e97bc01e70d8d5491e640167c96a8a0baa842cfd552321a9c2450576126311e071680a1258032219c6490b663c1dab8b90100000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000080000000000000000000000000000000000000000000000000200000000000000000008000000000040000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000084000000000010020000000000000000000000000000000000020000000200000000200000000000000000000000000000000000000000400000000000000000000000008727472e1db3626a83ed14f18401c9c3808401c9a205846322c96292e4b883e5bda9e7a59ee4bb99e9b1bc460021a04cbec03dddd4b939730a7fe6048729604d4266e82426d472a2b2024f3cc4043f8862a3ee77461d4fc9850a1a4e5f06";
}
