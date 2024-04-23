use alloy_primitives::B256;
use rust_embed::RustEmbed;
use std::path::PathBuf;

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, VariableList};
use tokio::sync::mpsc;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::{
    constants::{EPOCH_SIZE, MERGE_BLOCK_NUMBER},
    merkle::proof::{verify_merkle_proof, MerkleTree},
};
use ethportal_api::{
    types::{
        execution::{
            accumulator::EpochAccumulator,
            header::Header,
            header_with_proof::{BlockHeaderProof, HeaderWithProof},
        },
        jsonrpc::{endpoints::HistoryEndpoint, request::HistoryJsonRpcRequest},
    },
    utils::bytes::hex_decode,
    EpochAccumulatorKey, HistoryContentKey,
};

/// SSZ List[Hash256, max_length = MAX_HISTORICAL_EPOCHS]
/// List of historical epoch accumulator merkle roots preceding current epoch.
pub type HistoricalEpochRoots = VariableList<tree_hash::Hash256, typenum::U131072>;

#[derive(RustEmbed)]
#[folder = "src/assets/"]
#[prefix = "validation_assets/"]
struct TrinValidationAssets;

/// SSZ Container
/// Primary datatype used to maintain record of historical and current epoch.
/// Verifies canonical-ness of a given header.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, Deserialize, Serialize, TreeHash)]
pub struct MasterAccumulator {
    pub historical_epochs: HistoricalEpochRoots,
}

impl Default for MasterAccumulator {
    fn default() -> Self {
        let raw = TrinValidationAssets::get("validation_assets/merge_macc.bin")
            .expect("Unable to find default master accumulator");
        MasterAccumulator::from_ssz_bytes(raw.data.as_ref())
            .expect("Unable to decode default master accumulator")
    }
}

impl MasterAccumulator {
    /// Load default trusted master acc
    pub fn try_from_file(master_acc_path: PathBuf) -> anyhow::Result<MasterAccumulator> {
        let raw = TrinValidationAssets::get(&(*master_acc_path).display().to_string()[..])
            .ok_or_else(|| {
                anyhow!("Unable to find master accumulator at path: {master_acc_path:?}")
            })?;
        MasterAccumulator::from_ssz_bytes(raw.data.as_ref())
            .map_err(|err| anyhow!("Unable to decode master accumulator: {err:?}"))
    }

    /// Number of the last block to be included in the accumulator
    pub fn height(&self) -> u64 {
        MERGE_BLOCK_NUMBER
    }

    fn get_epoch_index_of_header(&self, header: &Header) -> u64 {
        header.number / EPOCH_SIZE as u64
    }

    pub async fn lookup_premerge_hash_by_number(
        &self,
        block_number: u64,
        history_jsonrpc_tx: mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    ) -> anyhow::Result<B256> {
        if block_number > MERGE_BLOCK_NUMBER {
            return Err(anyhow!("Post-merge blocks are not supported."));
        }
        let rel_index = block_number % EPOCH_SIZE as u64;
        let epoch_index = block_number / EPOCH_SIZE as u64;
        let epoch_hash = self.historical_epochs[epoch_index as usize];
        let epoch_acc = self
            .lookup_epoch_acc(epoch_hash, history_jsonrpc_tx)
            .await?;
        Ok(epoch_acc[rel_index as usize].block_hash)
    }

    pub fn validate_header_with_proof(&self, hwp: &HeaderWithProof) -> anyhow::Result<()> {
        match &hwp.proof {
            BlockHeaderProof::AccumulatorProof(proof) => {
                if hwp.header.number > MERGE_BLOCK_NUMBER {
                    return Err(anyhow!("Invalid proof type found for post-merge header."));
                }
                // Look up historical epoch hash for header from master accumulator
                let gen_index = calculate_generalized_index(&hwp.header);
                let epoch_index = self.get_epoch_index_of_header(&hwp.header) as usize;
                let epoch_hash = self.historical_epochs[epoch_index];

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

    pub async fn lookup_epoch_acc(
        &self,
        epoch_hash: B256,
        history_jsonrpc_tx: mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    ) -> anyhow::Result<EpochAccumulator> {
        let content_key = HistoryContentKey::EpochAccumulator(EpochAccumulatorKey { epoch_hash });
        let endpoint = HistoryEndpoint::RecursiveFindContent(content_key);
        let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
        let request = HistoryJsonRpcRequest {
            endpoint,
            resp: resp_tx,
        };
        history_jsonrpc_tx.send(request)?;

        let epoch_acc_ssz = match resp_rx.recv().await {
            Some(val) => {
                val.map_err(|msg| anyhow!("Chain history subnetwork request error: {:?}", msg))?
            }
            None => return Err(anyhow!("No response from chain history subnetwork")),
        };
        let epoch_acc_ssz = epoch_acc_ssz
            .as_str()
            .ok_or_else(|| anyhow!("Invalid epoch acc received from chain history network"))?;
        let epoch_acc_ssz = hex_decode(epoch_acc_ssz)?;
        EpochAccumulator::from_ssz_bytes(&epoch_acc_ssz).map_err(|msg| {
            anyhow!(
                "Invalid epoch acc received from chain history network: {:?}",
                msg
            )
        })
    }

    pub async fn generate_proof(
        &self,
        header: &Header,
        history_jsonrpc_tx: mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    ) -> anyhow::Result<[B256; 15]> {
        if header.number > MERGE_BLOCK_NUMBER {
            return Err(anyhow!("Unable to generate proof for post-merge header."));
        }
        // Fetch epoch accumulator for header
        let epoch_index = self.get_epoch_index_of_header(header);
        let epoch_hash = self.historical_epochs[epoch_index as usize];
        let epoch_acc = self
            .lookup_epoch_acc(epoch_hash, history_jsonrpc_tx)
            .await?;

        // Validate epoch accumulator hash matches historical hash from master accumulator
        let epoch_index = self.get_epoch_index_of_header(header);
        let epoch_hash = self.historical_epochs[epoch_index as usize];
        if epoch_acc.tree_hash_root() != epoch_hash {
            return Err(anyhow!(
                "Epoch acc hash sourced from network doesn't match historical hash in master acc."
            ));
        }
        MasterAccumulator::construct_proof(header, &epoch_acc)
    }

    pub fn construct_proof(
        header: &Header,
        epoch_acc: &EpochAccumulator,
    ) -> anyhow::Result<[B256; 15]> {
        // Validate header hash matches historical hash from epoch accumulator
        let hr_index = (header.number % EPOCH_SIZE as u64) as usize;
        let header_record = epoch_acc[hr_index];
        if header_record.block_hash != header.hash() {
            return Err(anyhow!(
                "Block hash doesn't match historical header hash found in epoch acc."
            ));
        }

        // Create a merkle tree from epoch accumulator.
        // To construct a valid proof for the header hash, we add both the hash and the total
        // difficulty as individual leaves for each header record. This will ensure that the
        // total difficulty is included as the first element in the proof.
        let mut leaves = vec![];
        // iterate over every header record in the epoch acc
        for record in epoch_acc.into_iter() {
            // add the block hash as a leaf
            leaves.push(record.block_hash);
            // convert total difficulty to B256
            let leaf = B256::from_slice(record.total_difficulty.as_le_slice());
            // add the total difficulty as a leaf
            leaves.push(leaf);
        }
        // Create the merkle tree from leaves
        let merkle_tree = MerkleTree::create(&leaves, 14);

        // Multiply hr_index by 2 b/c we're now using a depth of 14 rather than the original 13
        let hr_index = hr_index * 2;

        // Generating the proof for the value at hr_index (leaf)
        let (leaf, mut proof) = merkle_tree
            .generate_proof(hr_index, 14)
            .map_err(|err| anyhow!("Unable to generate proof for given index: {err:?}"))?;
        // Validate that the value the proof is for (leaf) is the header hash
        assert_eq!(leaf, header.hash());

        // Add the be encoded EPOCH_SIZE to proof to comply with ssz merkleization spec
        // https://github.com/ethereum/consensus-specs/blob/dev/ssz/merkle-proofs.md#ssz-object-to-index
        proof.push(B256::from_slice(&hex_decode(
            "0x0020000000000000000000000000000000000000000000000000000000000000",
        )?));
        let final_proof: [B256; 15] = proof
            .try_into()
            .map_err(|_| anyhow!("Invalid proof length."))?;
        Ok(final_proof)
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

    use alloy_primitives::{Address, Bloom, U256};
    use alloy_rlp::Decodable;
    use rstest::*;
    use serde_json::json;
    use ssz::Decode;

    use crate::constants::DEFAULT_MASTER_ACC_HASH;
    use ethportal_api::{
        types::execution::header_with_proof::{
            AccumulatorProof, BlockHeaderProof, HeaderWithProof, SszNone,
        },
        utils::bytes::hex_encode,
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
        let trin_macc = get_mainnet_master_acc();
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
        let trin_proof = trin_macc.generate_proof(&header, tx).await.unwrap();
        let fluffy_proof = match fluffy_hwp.proof {
            BlockHeaderProof::AccumulatorProof(val) => val,
            _ => panic!("test reached invalid state"),
        };
        assert_eq!(trin_proof, fluffy_proof.proof);
        let hwp = HeaderWithProof {
            header,
            proof: BlockHeaderProof::AccumulatorProof(AccumulatorProof { proof: trin_proof }),
        };
        trin_macc.validate_header_with_proof(&hwp).unwrap();
    }

    #[tokio::test]
    async fn invalidate_invalid_proofs() {
        let trin_macc = get_mainnet_master_acc();
        let (tx, mut rx) = mpsc::unbounded_channel::<HistoryJsonRpcRequest>();
        tokio::spawn(async move {
            spawn_mock_epoch_acc_lookup(&mut rx).await;
        });
        let header = get_header(1_000_001);
        let mut proof = trin_macc.generate_proof(&header, tx).await.unwrap();
        proof.swap(0, 1);
        let hwp = HeaderWithProof {
            header,
            proof: BlockHeaderProof::AccumulatorProof(AccumulatorProof { proof }),
        };
        assert!(trin_macc
            .validate_header_with_proof(&hwp)
            .unwrap_err()
            .to_string()
            .contains("Merkle proof validation failed"));
    }

    #[tokio::test]
    #[should_panic(expected = "Missing accumulator proof for pre-merge header.")]
    async fn master_accumulator_cannot_validate_pre_merge_header_missing_proof() {
        let master_acc = get_mainnet_master_acc();
        let header = get_header(1_000_001);
        let hwp = HeaderWithProof {
            header,
            proof: BlockHeaderProof::None(SszNone::default()),
        };
        master_acc.validate_header_with_proof(&hwp).unwrap();
    }

    #[tokio::test]
    async fn master_accumulator_validates_post_merge_header_without_proof() {
        let master_acc = get_mainnet_master_acc();
        let future_height = MERGE_BLOCK_NUMBER + 1;
        let future_header = generate_random_header(&future_height);
        let future_hwp = HeaderWithProof {
            header: future_header,
            proof: BlockHeaderProof::None(SszNone::default()),
        };
        master_acc.validate_header_with_proof(&future_hwp).unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Invalid proof type found for post-merge header.")]
    async fn master_accumulator_invalidates_post_merge_header_with_accumulator_proof() {
        let master_acc = get_mainnet_master_acc();
        let future_height = MERGE_BLOCK_NUMBER + 1;
        let future_header = generate_random_header(&future_height);
        let future_hwp = HeaderWithProof {
            header: future_header,
            proof: BlockHeaderProof::AccumulatorProof(AccumulatorProof {
                proof: [B256::ZERO; 15],
            }),
        };
        master_acc.validate_header_with_proof(&future_hwp).unwrap();
    }

    //
    // Testing utils
    //
    fn get_mainnet_master_acc() -> MasterAccumulator {
        let master_acc = MasterAccumulator::default();
        assert_eq!(
            master_acc.tree_hash_root(),
            B256::from_str(DEFAULT_MASTER_ACC_HASH).unwrap()
        );
        master_acc
    }

    fn get_header(number: u64) -> Header {
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
                panic!("Test run failed: Unable to get response from master_acc validation.")
            }
        }
    }
}
