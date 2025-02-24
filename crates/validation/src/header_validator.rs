use alloy::primitives::B256;
use anyhow::anyhow;
use ethportal_api::{
    consensus::historical_summaries::HistoricalSummaries,
    types::execution::header_with_proof_new::{
        BlockHeaderProof, BlockProofHistoricalRoots, BlockProofHistoricalSummaries, HeaderWithProof,
    },
    Header,
};

use crate::{
    accumulator::PreMergeAccumulator,
    constants::{
        CAPELLA_FORK_EPOCH, EPOCH_SIZE, MERGE_BLOCK_NUMBER, SHANGHAI_BLOCK_NUMBER, SLOTS_PER_EPOCH,
    },
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

    pub fn validate_header_with_proof(&self, hwp: &HeaderWithProof) -> anyhow::Result<()> {
        match &hwp.proof {
            BlockHeaderProof::HistoricalHashes(proof) => {
                if hwp.header.number > MERGE_BLOCK_NUMBER {
                    return Err(anyhow!("Invalid proof type found for post-merge header."));
                }
                // Look up historical epoch hash for header from pre-merge accumulator
                let gen_index = calculate_generalized_index(&hwp.header);
                let epoch_index =
                    self.pre_merge_acc.get_epoch_index_of_header(&hwp.header) as usize;
                let epoch_hash = self.pre_merge_acc.historical_epochs[epoch_index];

                match verify_merkle_proof(
                    hwp.header.hash(),
                    proof,
                    15,
                    gen_index as usize,
                    epoch_hash,
                ) {
                    true => Ok(()),
                    false => Err(anyhow!(
                        "Merkle proof validation failed for pre-merge header"
                    )),
                }
            }
            BlockHeaderProof::HistoricalRoots(proof) => self.verify_post_merge_pre_capella_header(
                hwp.header.number,
                hwp.header.hash(),
                proof,
            ),
            BlockHeaderProof::HistoricalSummaries(_) => {
                if hwp.header.number < SHANGHAI_BLOCK_NUMBER {
                    return Err(anyhow!(
                        "Invalid BlockProofHistoricalSummaries found for pre-Shanghai header."
                    ));
                }
                // TODO: Validation for post-Capella headers is not implemented
                Ok(())
            }
        }
    }

    /// A method to verify the chain of proofs for post-merge/pre-Capella execution headers.
    fn verify_post_merge_pre_capella_header(
        &self,
        block_number: u64,
        header_hash: B256,
        proof: &BlockProofHistoricalRoots,
    ) -> anyhow::Result<()> {
        if block_number <= MERGE_BLOCK_NUMBER {
            return Err(anyhow!(
                "Invalid HistoricalRootsBlockProof found for pre-merge header."
            ));
        }
        if block_number >= SHANGHAI_BLOCK_NUMBER {
            return Err(anyhow!(
                "Invalid HistoricalRootsBlockProof found for post-Shanghai header."
            ));
        }

        // Verify the chain of proofs for post-merge/pre-capella block header
        Self::verify_beacon_block_proof(
            header_hash,
            &proof.execution_block_proof,
            proof.beacon_block_root,
        )?;

        let block_root_index = proof.slot % EPOCH_SIZE;
        let gen_index = 2 * EPOCH_SIZE + block_root_index;
        let historical_root_index = proof.slot / EPOCH_SIZE;
        let historical_root =
            self.historical_roots_acc.historical_roots[historical_root_index as usize];

        if !verify_merkle_proof(
            proof.beacon_block_root,
            &proof.beacon_block_proof,
            14,
            gen_index as usize,
            historical_root,
        ) {
            return Err(anyhow!(
                "Merkle proof validation failed for HistoricalRootsProof"
            ));
        }

        Ok(())
    }

    /// A method to verify the chain of proofs for post-Capella execution headers.
    #[allow(dead_code)] // TODO: Remove this when used
    fn verify_post_capella_header(
        &self,
        block_number: u64,
        header_hash: B256,
        proof: &BlockProofHistoricalSummaries,
        historical_summaries: HistoricalSummaries,
    ) -> anyhow::Result<()> {
        if block_number < SHANGHAI_BLOCK_NUMBER {
            return Err(anyhow!(
                "Invalid HistoricalSummariesBlockProof found for pre-Shanghai header."
            ));
        }

        // Verify the chain of proofs for post-merge/pre-capella block header
        Self::verify_beacon_block_proof(
            header_hash,
            &proof.execution_block_proof,
            proof.beacon_block_root,
        )?;

        let block_root_index = proof.slot % EPOCH_SIZE;
        let gen_index = EPOCH_SIZE + block_root_index;
        let historical_summary_index =
            (proof.slot - CAPELLA_FORK_EPOCH * SLOTS_PER_EPOCH) / EPOCH_SIZE;
        let historical_summary =
            historical_summaries[historical_summary_index as usize].block_summary_root;

        if !verify_merkle_proof(
            proof.beacon_block_root,
            &proof.beacon_block_proof,
            13,
            gen_index as usize,
            historical_summary,
        ) {
            return Err(anyhow!(
                "Merkle proof validation failed for HistoricalSummariesProof"
            ));
        }

        Ok(())
    }

    /// Verify that the execution block header is included in the beacon block
    fn verify_beacon_block_proof(
        header_hash: B256,
        block_body_proof: &[B256],
        block_body_root: B256,
    ) -> anyhow::Result<()> {
        // BeaconBlock level:
        // - 8 as there are 5 fields
        // - 4 as index (pos) of field is 4
        // let gen_index_top_level = (1 * 1 * 8 + 4)
        // BeaconBlockBody level:
        // - 16 as there are 10 fields
        // - 9 as index (pos) of field is 9
        // let gen_index_mid_level = (gen_index_top_level * 1 * 16 + 9)
        // ExecutionPayload level:
        // - 16 as there are 14 fields
        // - 12 as pos of field is 12
        // let gen_index = (gen_index_mid_level * 1 * 16 + 12) = 3228
        let gen_index = 3228;

        if !verify_merkle_proof(
            header_hash,
            block_body_proof,
            block_body_proof.len(),
            gen_index,
            block_body_root,
        ) {
            return Err(anyhow!(
                "Merkle proof validation failed for BeaconBlockProof"
            ));
        }
        Ok(())
    }
}

fn calculate_generalized_index(header: &Header) -> u64 {
    // Calculate generalized index for header
    // https://github.com/ethereum/consensus-specs/blob/v0.11.1/ssz/merkle-proofs.md#generalized-merkle-tree-index
    let hr_index = header.number % EPOCH_SIZE;
    (EPOCH_SIZE * 2 * 2) + (hr_index * 2)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use std::{fs, path::PathBuf, str::FromStr};

    use alloy::{
        primitives::{Address, Bloom, B256, U256},
        rlp::Decodable,
    };
    use ethportal_api::{
        types::execution::{
            accumulator::EpochAccumulator,
            header_with_proof_new::{BlockHeaderProof, HeaderWithProof},
        },
        utils::bytes::{hex_decode, hex_encode},
        HistoryContentKey, OverlayContentKey,
    };
    use rstest::*;
    use serde_json::Value;
    use ssz::{Decode, Encode};
    use tree_hash::TreeHash;
    use trin_utils::submodules::{
        read_portal_spec_tests_file, read_portal_spec_tests_file_as_bytes,
    };

    use super::*;
    use crate::constants::DEFAULT_PRE_MERGE_ACC_HASH;

    const SPEC_TESTS_DIR: &str = "tests/mainnet/history";

    #[rstest]
    #[case(1_000_001)]
    #[case(1_000_002)]
    #[case(1_000_003)]
    #[case(1_000_004)]
    #[case(1_000_005)]
    #[case(1_000_006)]
    #[case(1_000_007)]
    #[case(1_000_008)]
    #[case(1_000_009)]
    #[case(1_000_010)]
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
        let trin_proof = PreMergeAccumulator::construct_proof(&header, &epoch_accumulator).unwrap();
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
    #[case(HEADER_RLP_15_537_392, 15_537_392)]
    #[case(HEADER_RLP_15_537_393, 15_537_393)]
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
    async fn invalidate_invalid_proofs() {
        let header_validator = get_mainnet_header_validator();
        let header = get_header(1_000_001);
        let epoch_accumulator = read_epoch_accumulator_122();
        let mut proof = PreMergeAccumulator::construct_proof(&header, &epoch_accumulator).unwrap();
        proof.swap(0, 1);
        let hwp = HeaderWithProof {
            header,
            proof: BlockHeaderProof::HistoricalHashes(proof),
        };
        assert!(header_validator
            .validate_header_with_proof(&hwp)
            .unwrap_err()
            .to_string()
            .contains("Merkle proof validation failed"));
    }

    #[tokio::test]
    #[should_panic(expected = "Invalid proof type found for post-merge header.")]
    async fn header_validator_invalidates_post_merge_header_with_accumulator_proof() {
        let header_validator = get_mainnet_header_validator();
        let future_height = MERGE_BLOCK_NUMBER + 1;
        let future_header = generate_random_header(&future_height);
        let future_hwp = HeaderWithProof {
            header: future_header,
            proof: BlockHeaderProof::HistoricalHashes(Default::default()),
        };
        header_validator
            .validate_header_with_proof(&future_hwp)
            .unwrap();
    }
    #[tokio::test]
    async fn header_validator_validate_post_merge_pre_capella_header() {
        let header_validator = get_mainnet_header_validator();

        // Read the historical roots block proof from a test file
        let file = read_portal_spec_tests_file(PathBuf::from(SPEC_TESTS_DIR).join(
            "headers_with_proof/block_proofs_bellatrix/beacon_block_proof-15539558-cdf9ed89b0c43cda17398dc4da9cfc505e5ccd19f7c39e3b43474180f1051e01.yaml",
        ))
        .unwrap();
        let value: serde_yaml::Value = serde_yaml::from_str(&file).unwrap();
        let block_number: u64 = 15539558;
        let header_hash = value
            .get("execution_block_header")
            .unwrap()
            .as_str()
            .unwrap();
        let header_hash = B256::from_str(header_hash).unwrap();
        let historical_roots_block_proof: BlockProofHistoricalRoots =
            serde_yaml::from_value(value).unwrap();

        header_validator
            .verify_post_merge_pre_capella_header(
                block_number,
                header_hash,
                &historical_roots_block_proof,
            )
            .unwrap();

        // Test for invalid block numbers
        let validator_result = header_validator.verify_post_merge_pre_capella_header(
            SHANGHAI_BLOCK_NUMBER,
            header_hash,
            &historical_roots_block_proof,
        );
        assert!(validator_result.is_err());

        let validator_result = header_validator.verify_post_merge_pre_capella_header(
            MERGE_BLOCK_NUMBER,
            header_hash,
            &historical_roots_block_proof,
        );
        assert!(validator_result.is_err());
    }

    #[rstest]
    #[case(17034870)]
    #[case(17042287)]
    #[case(17062257)]
    #[tokio::test]
    async fn header_validator_validate_post_capella_header(#[case] block_number: u64) {
        let header_validator = get_mainnet_header_validator();

        // Read the historical roots block proof from a test file
        let file = read_portal_spec_tests_file(PathBuf::from(SPEC_TESTS_DIR).join(format!(
            "headers_with_proof/block_proofs_capella/beacon_block_proof-{block_number}.yaml"
        )))
        .unwrap();
        let value: serde_yaml::Value = serde_yaml::from_str(&file).unwrap();
        let header_hash = value
            .get("execution_block_header")
            .unwrap()
            .as_str()
            .unwrap();
        let header_hash = B256::from_str(header_hash).unwrap();
        let historical_summaries_block_proof: BlockProofHistoricalSummaries =
            serde_yaml::from_value(value).unwrap();

        // Load historical summaries from ssz file
        let historical_summaries_bytes =
            read_portal_spec_tests_file_as_bytes(PathBuf::from(SPEC_TESTS_DIR).join(
                "headers_with_proof/block_proofs_capella/historical_summaries_at_slot_8953856.ssz",
            ))
            .expect("cannot load HistoricalSummaries bytes from test file");
        let historical_summaries = HistoricalSummaries::from_ssz_bytes(&historical_summaries_bytes)
            .expect("cannot decode HistoricalSummaries bytes");

        header_validator
            .verify_post_capella_header(
                block_number,
                header_hash,
                &historical_summaries_block_proof,
                historical_summaries.clone(),
            )
            .unwrap();

        // Test for invalid block numbers
        let validator_result = header_validator.verify_post_capella_header(
            SHANGHAI_BLOCK_NUMBER - 1,
            header_hash,
            &historical_summaries_block_proof,
            historical_summaries,
        );
        assert!(validator_result.is_err());
    }

    //
    // Testing utils
    //
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
            uncles_hash: B256::random(),
            author: Address::random(),
            state_root: B256::random(),
            transactions_root: B256::random(),
            receipts_root: B256::random(),
            logs_bloom: Bloom::ZERO,
            difficulty: U256::from(1),
            number: *height,
            gas_limit: U256::from(1),
            gas_used: U256::from(1),
            timestamp: 1,
            extra_data: vec![],
            mix_hash: None,
            nonce: None,
            base_fee_per_gas: None,
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
        }
    }

    fn read_epoch_accumulator_122() -> EpochAccumulator {
        let epoch_acc_bytes = read_portal_spec_tests_file_as_bytes(
            PathBuf::from(SPEC_TESTS_DIR).join("accumulator/epoch-record-00122.ssz"),
        )
        .unwrap();
        EpochAccumulator::from_ssz_bytes(&epoch_acc_bytes).unwrap()
    }

    const HEADER_RLP_15_537_392: &str = "0xf90218a02f1dc309c7cc0a5a2e3b3dd9315fea0ffbc53c56f9237f3ca11b20de0232f153a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ea674fdde714fd979de3edf0f56aa9716b898ec8a0fee48a40a2765ab31fcd06ab6956341d13dc2c4b9762f2447aa425bb1c089b30a082864b3a65d1ac1917c426d48915dca0fc966fbf3f30fd051659f35dc3fd9be1a013c10513b52358022f800e2f9f1c50328798427b1b4a1ebbbd20b7417fb9719db90100ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff872741c5e4f6c39283ed14f08401c9c3808401c9a028846322c95c8f617369612d65617374322d31763932a02df332ffb74ecd15c9873d3f6153b878e1c514495dfb6e89ad88e574582b02a488232b0043952c93d98508fb17c6ee";
    const HEADER_RLP_15_537_393: &str = "0xf9021ba02b3ea3cd4befcab070812443affb08bf17a91ce382c714a536ca3cacab82278ba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794829bd824b016326a401d083b33d092293333a830a04919dafa6ac8becfbbd0c2808f6c9511a057c21e42839caff5dfb6d3ef514951a0dd5eec02b019ff76e359b09bfa19395a2a0e97bc01e70d8d5491e640167c96a8a0baa842cfd552321a9c2450576126311e071680a1258032219c6490b663c1dab8b90100000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000080000000000000000000000000000000000000000000000000200000000000000000008000000000040000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000084000000000010020000000000000000000000000000000000020000000200000000200000000000000000000000000000000000000000400000000000000000000000008727472e1db3626a83ed14f18401c9c3808401c9a205846322c96292e4b883e5bda9e7a59ee4bb99e9b1bc460021a04cbec03dddd4b939730a7fe6048729604d4266e82426d472a2b2024f3cc4043f8862a3ee77461d4fc9850a1a4e5f06";
}
