use crate::{
    accumulator::PreMergeAccumulator,
    constants::{EPOCH_SIZE, MERGE_BLOCK_NUMBER},
    historical_roots_acc::HistoricalRootsAccumulator,
    merkle::proof::verify_merkle_proof,
};
use anyhow::anyhow;
use ethportal_api::{
    types::execution::header_with_proof::{BlockHeaderProof, HeaderWithProof},
    Header,
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
            BlockHeaderProof::PreMergeAccumulatorProof(proof) => {
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
                    &proof.proof,
                    15,
                    gen_index,
                    epoch_hash,
                ) {
                    true => Ok(()),
                    false => Err(anyhow!(
                        "Merkle proof validation failed for pre-merge header"
                    )),
                }
            }
            BlockHeaderProof::None(_) => {
                if hwp.header.number <= MERGE_BLOCK_NUMBER {
                    Err(anyhow!("Missing accumulator proof for pre-merge header."))
                } else {
                    // Skip validation for post-merge headers until proof format is finalized
                    Ok(())
                }
            }
            _ => unimplemented!("Unsupported proof type found."),
        }
    }
}

fn calculate_generalized_index(header: &Header) -> usize {
    // Calculate generalized index for header
    // https://github.com/ethereum/consensus-specs/blob/v0.11.1/ssz/merkle-proofs.md#generalized-merkle-tree-index
    let hr_index = header.number as usize % EPOCH_SIZE;
    (EPOCH_SIZE * 2 * 2) + (hr_index * 2)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use std::{fs, str::FromStr};

    use alloy_primitives::{Address, Bloom, B256, U256};
    use alloy_rlp::Decodable;
    use rstest::*;
    use serde_json::{json, Value};
    use ssz::Decode;
    use tokio::sync::mpsc;
    use tree_hash::TreeHash;

    use crate::constants::DEFAULT_PRE_MERGE_ACC_HASH;
    use ethportal_api::{
        types::{
            execution::header_with_proof::{
                BlockHeaderProof, HeaderWithProof, PreMergeAccumulatorProof, SszNone,
            },
            jsonrpc::{endpoints::HistoryEndpoint, request::HistoryJsonRpcRequest},
        },
        utils::bytes::{hex_decode, hex_encode},
        HistoryContentKey,
    };

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
        let file = fs::read_to_string("./src/assets/fluffy/header_with_proofs.json").unwrap();
        let json: Value = serde_json::from_str(&file).unwrap();
        let hwps = json.as_object().unwrap();
        let header_validator = get_mainnet_header_validator();
        let (tx, mut rx) = mpsc::unbounded_channel::<HistoryJsonRpcRequest>();
        tokio::spawn(async move {
            spawn_mock_epoch_acc_lookup(&mut rx).await;
        });
        let obj = hwps.get(&block_number.to_string()).unwrap();
        // Validate content_key decodes
        let raw_ck = obj.get("content_key").unwrap().as_str().unwrap();
        let raw_ck = hex_decode(raw_ck).unwrap();
        let ck = HistoryContentKey::try_from(raw_ck).unwrap();
        match ck {
            HistoryContentKey::BlockHeaderWithProof(_) => (),
            _ => panic!("Invalid test, content key decoded improperly"),
        }
        let raw_fluffy_hwp = obj.get("value").unwrap().as_str().unwrap();
        let fluffy_hwp =
            HeaderWithProof::from_ssz_bytes(&hex_decode(raw_fluffy_hwp).unwrap()).unwrap();
        let header = get_header(block_number);
        let trin_proof = header_validator
            .pre_merge_acc
            .generate_proof(&header, tx)
            .await
            .unwrap();
        let fluffy_proof = match fluffy_hwp.proof {
            BlockHeaderProof::PreMergeAccumulatorProof(val) => val,
            _ => panic!("test reached invalid state"),
        };
        assert_eq!(trin_proof, fluffy_proof.proof);
        let hwp = HeaderWithProof {
            header,
            proof: BlockHeaderProof::PreMergeAccumulatorProof(PreMergeAccumulatorProof {
                proof: trin_proof,
            }),
        };
        header_validator.validate_header_with_proof(&hwp).unwrap();
    }

    #[tokio::test]
    async fn invalidate_invalid_proofs() {
        let header_validator = get_mainnet_header_validator();
        let (tx, mut rx) = mpsc::unbounded_channel::<HistoryJsonRpcRequest>();
        tokio::spawn(async move {
            spawn_mock_epoch_acc_lookup(&mut rx).await;
        });
        let header = get_header(1_000_001);
        let mut proof = header_validator
            .pre_merge_acc
            .generate_proof(&header, tx)
            .await
            .unwrap();
        proof.swap(0, 1);
        let hwp = HeaderWithProof {
            header,
            proof: BlockHeaderProof::PreMergeAccumulatorProof(PreMergeAccumulatorProof { proof }),
        };
        assert!(header_validator
            .validate_header_with_proof(&hwp)
            .unwrap_err()
            .to_string()
            .contains("Merkle proof validation failed"));
    }

    #[tokio::test]
    #[should_panic(expected = "Missing accumulator proof for pre-merge header.")]
    async fn header_validator_cannot_validate_merge_header_missing_proof() {
        let header_validator = get_mainnet_header_validator();
        let header = get_header(1_000_001);
        let hwp = HeaderWithProof {
            header,
            proof: BlockHeaderProof::None(SszNone::default()),
        };
        header_validator.validate_header_with_proof(&hwp).unwrap();
    }

    #[tokio::test]
    async fn header_validator_validates_post_merge_header_without_proof() {
        let header_validator = get_mainnet_header_validator();
        let future_height = MERGE_BLOCK_NUMBER + 1;
        let future_header = generate_random_header(&future_height);
        let future_hwp = HeaderWithProof {
            header: future_header,
            proof: BlockHeaderProof::None(SszNone::default()),
        };
        header_validator
            .validate_header_with_proof(&future_hwp)
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Invalid proof type found for post-merge header.")]
    async fn header_validator_invalidates_post_merge_header_with_accumulator_proof() {
        let header_validator = get_mainnet_header_validator();
        let future_height = MERGE_BLOCK_NUMBER + 1;
        let future_header = generate_random_header(&future_height);
        let future_hwp = HeaderWithProof {
            header: future_header,
            proof: BlockHeaderProof::PreMergeAccumulatorProof(PreMergeAccumulatorProof {
                proof: [B256::ZERO; 15],
            }),
        };
        header_validator
            .validate_header_with_proof(&future_hwp)
            .unwrap();
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

    async fn spawn_mock_epoch_acc_lookup(rx: &mut mpsc::UnboundedReceiver<HistoryJsonRpcRequest>) {
        match rx.recv().await {
            Some(request) => match request.endpoint {
                HistoryEndpoint::RecursiveFindContent(content_key) => {
                    let json_value = serde_json::to_value(content_key).unwrap();
                    let response = json_value.as_str().unwrap();
                    let epoch_acc_hash = response.trim_start_matches("0x03");
                    let epoch_acc_hash = B256::from_str(epoch_acc_hash).unwrap();
                    let epoch_acc_path = format!("./src/assets/epoch_accs/{epoch_acc_hash}.bin");
                    let epoch_acc = fs::read(epoch_acc_path).unwrap();
                    let epoch_acc = hex_encode(epoch_acc);
                    let content: Value = json!(epoch_acc);
                    let _ = request.resp.send(Ok(content));
                }
                _ => panic!("Unexpected request endpoint"),
            },
            None => {
                panic!("Test run failed: Unable to get response from pre_merge_acc validation.")
            }
        }
    }
}
