use alloy::{consensus::Header, primitives::B256};
use jsonrpsee::core::Serialize;
use serde::Deserialize;
use ssz::SszDecoderBuilder;
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, FixedVector, VariableList};
use tree_hash::TreeHash;

use crate::{
    consensus::beacon_state::RootsPerHistoricalRoot,
    types::{
        bytes::ByteList1024,
        consensus::{
            beacon_block::{BeaconBlockBellatrix, BeaconBlockCapella},
            beacon_state::HistoricalBatch,
            proof::build_merkle_proof_for_index,
        },
        execution::{
            block_body::{MERGE_TIMESTAMP, SHANGHAI_TIMESTAMP},
            ssz_header,
        },
    },
};

/// The accumulator proof for EL BlockHeader for the pre-merge blocks.
pub type BlockProofHistoricalHashesAccumulator = FixedVector<B256, typenum::U15>;

/// Proof that EL block_hash is in BeaconBlock -> BeaconBlockBody -> ExecutionPayload
/// for TheMerge until Capella
pub type ExecutionBlockProof = FixedVector<B256, typenum::U11>;
/// Proof that EL block_hash is in BeaconBlock -> BeaconBlockBody -> ExecutionPayload
/// for Post-Capella
pub type ExecutionBlockProofCapella = VariableList<B256, typenum::U12>;
/// Proof that BeaconBlock root is part of historical_summaries and thus canonical
/// for Capella and onwards
pub type BeaconBlockProofHistoricalSummaries = FixedVector<B256, typenum::U13>;
/// Proof that BeaconBlock root is part of historical_roots and thus canonical
/// from TheMerge until Capella -> Bellatrix fork.
pub type BeaconBlockProofHistoricalRoots = FixedVector<B256, typenum::U14>;

/// A block header with accumulator proof.
/// Type definition:
/// https://github.com/status-im/nimbus-eth1/blob/master/fluffy/network/history/history_content.nim#L136
#[derive(Debug, Clone, PartialEq, Eq, Encode, Deserialize)]
pub struct HeaderWithProof {
    #[ssz(with = "ssz_header")]
    pub header: Header,
    pub proof: BlockHeaderProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum BlockHeaderProof {
    // Pre-Merge
    HistoricalHashes(BlockProofHistoricalHashesAccumulator),
    // Merge -> Capella
    HistoricalRoots(BlockProofHistoricalRoots),
    // Post-Capella
    HistoricalSummaries(BlockProofHistoricalSummaries),
}

impl ssz::Decode for HeaderWithProof {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);

        builder.register_anonymous_variable_length_item()?;
        builder.register_anonymous_variable_length_item()?;

        let mut decoder = builder.build()?;

        let header = decoder.decode_next_with(ssz_header::decode::from_ssz_bytes)?;
        let proof = decoder.decode_next::<ByteList1024>()?;
        let proof = if header.timestamp <= MERGE_TIMESTAMP {
            BlockHeaderProof::HistoricalHashes(
                BlockProofHistoricalHashesAccumulator::from_ssz_bytes(&proof)?,
            )
        } else if header.timestamp <= SHANGHAI_TIMESTAMP {
            BlockHeaderProof::HistoricalRoots(BlockProofHistoricalRoots::from_ssz_bytes(&proof)?)
        } else {
            BlockHeaderProof::HistoricalSummaries(BlockProofHistoricalSummaries::from_ssz_bytes(
                &proof,
            )?)
        };
        Ok(Self { header, proof })
    }
}

impl ssz::Encode for BlockHeaderProof {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        match self {
            BlockHeaderProof::HistoricalHashes(proof) => {
                proof.ssz_append(buf);
            }
            BlockHeaderProof::HistoricalRoots(proof) => {
                proof.ssz_append(buf);
            }
            BlockHeaderProof::HistoricalSummaries(proof) => {
                proof.ssz_append(buf);
            }
        }
    }

    fn ssz_bytes_len(&self) -> usize {
        match self {
            BlockHeaderProof::HistoricalHashes(proof) => proof.ssz_bytes_len(),
            BlockHeaderProof::HistoricalRoots(proof) => proof.ssz_bytes_len(),
            BlockHeaderProof::HistoricalSummaries(proof) => proof.ssz_bytes_len(),
        }
    }
}

/// The struct holds a chain of proofs. This chain of proofs allows for verifying that an EL
/// `BlockHeader` is part of the canonical chain. The only requirement is having access to the
/// beacon chain `historical_roots`.
///
/// Proof for EL BlockHeader from TheMerge until Capella
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct BlockProofHistoricalRoots {
    /// Proof that the BeaconBlock is part of the historical roots
    /// and thus part of the canonical chain.
    pub beacon_block_proof: BeaconBlockProofHistoricalRoots,
    /// hash_tree_root of BeaconBlock used to verify the proofs
    pub beacon_block_root: B256,
    /// Proof that EL BlockHash is part of the BeaconBlock
    pub execution_block_proof: ExecutionBlockProof,
    /// Slot of BeaconBlock, used to calculate the historical_roots index
    pub slot: u64,
}

/// The struct holds a chain of proofs. This chain of proofs allows for verifying that an EL
/// `BlockHeader` is part of the canonical chain. The only requirement is having access to the
/// beacon chain `historical_summaries`.
///
/// Proof for EL BlockHeader for Capella and onwards
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct BlockProofHistoricalSummaries {
    /// Proof that the BeaconBlock is part of the historical_summaries
    /// and thus part of the canonical chain.
    pub beacon_block_proof: BeaconBlockProofHistoricalSummaries,
    /// hash_tree_root of BeaconBlock used to verify the proofs
    pub beacon_block_root: B256,
    /// Proof that EL BlockHash is part of the BeaconBlock
    pub execution_block_proof: ExecutionBlockProofCapella,
    /// Slot of BeaconBlock, used to calculate the historical_summaries index
    pub slot: u64,
}

/// Builds `BlockProofHistoricalRoots` for a given slot.
pub fn build_historical_roots_proof(
    slot: u64,
    historical_batch: &HistoricalBatch,
    beacon_block: &BeaconBlockBellatrix,
) -> BlockProofHistoricalRoots {
    let beacon_block_proof =
        BeaconBlockProofHistoricalRoots::new(historical_batch.build_block_root_proof(slot % 8192))
            .expect("error creating BeaconBlockProofHistoricalRoots");

    // execution block proof
    let execution_block_proof =
        ExecutionBlockProof::new(beacon_block.build_execution_block_hash_proof())
            .expect("error creating ExecutionBlockProof");

    BlockProofHistoricalRoots {
        beacon_block_proof,
        beacon_block_root: beacon_block.tree_hash_root(),
        execution_block_proof,
        slot,
    }
}

/// Builds `BlockProofHistoricalSummaries` for a given slot.
///
/// The `block_roots` represents the `block_roots` fields from `BeaconState`.
pub fn build_historical_summaries_proof(
    slot: u64,
    block_roots: &RootsPerHistoricalRoot,
    beacon_block: &BeaconBlockCapella,
) -> BlockProofHistoricalSummaries {
    let beacon_block_proof =
        build_merkle_proof_for_index(block_roots.clone(), slot as usize % 8192);
    let beacon_block_proof = BeaconBlockProofHistoricalSummaries::new(beacon_block_proof)
        .expect("error creating BeaconBlockProofHistoricalSummaries");

    let execution_block_proof =
        ExecutionBlockProofCapella::new(beacon_block.build_execution_block_hash_proof())
            .expect("error creating ExecutionBlockProofCapella");

    BlockProofHistoricalSummaries {
        beacon_block_proof,
        beacon_block_root: beacon_block.tree_hash_root(),
        execution_block_proof,
        slot,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::path::{Path, PathBuf};

    use alloy::{hex::FromHex, primitives::Bytes};
    use serde_json::Value;
    use ssz::Decode;

    use super::*;
    use crate::{
        consensus::beacon_state::BeaconStateCapella,
        test_utils::{read_bytes_from_tests_submodule, read_file_from_tests_submodule},
        utils::bytes::{hex_decode, hex_encode},
    };

    const TEST_DIR: &str = "tests/mainnet/history/headers_with_proof";

    #[test_log::test]
    fn decode_encode_headers_with_proof() {
        let file =
            read_file_from_tests_submodule(PathBuf::from(TEST_DIR).join("1000001-1000010.json"))
                .unwrap();
        let json: Value = serde_json::from_str(&file).unwrap();
        let hwps = json.as_object().unwrap();
        for (block_number, obj) in hwps {
            let block_number: u64 = block_number.parse().unwrap();
            let actual_hwp = obj.get("content_value").unwrap().as_str().unwrap();
            let hwp = HeaderWithProof::from_ssz_bytes(&hex_decode(actual_hwp).unwrap()).unwrap();
            assert_eq!(block_number, hwp.header.number);
            let encoded = hex_encode(ssz::Encode::as_ssz_bytes(&hwp));
            assert_eq!(encoded, actual_hwp);
        }
    }

    #[rstest::rstest]
    #[case(1000010)]
    #[case(14764013)]
    #[case(15537392)]
    #[case(15537393)]
    #[case(15539558)]
    #[case(15547621)]
    #[case(15555729)]
    #[case(17034870)]
    #[case(17042287)]
    #[case(17062257)]
    fn decode_encode_more_headers_with_proofs(#[case] block_number: u64) {
        let yaml: serde_yaml::Value =
            read_yaml_test_file(PathBuf::from(TEST_DIR).join(format!("{block_number}.yaml")));
        let actual_hwp = yaml["content_value"].as_str().unwrap();
        let header_with_proof =
            HeaderWithProof::from_ssz_bytes(&hex_decode(actual_hwp).unwrap()).unwrap();
        assert_eq!(header_with_proof.header.number, block_number);
        let encoded = hex_encode(ssz::Encode::as_ssz_bytes(&header_with_proof));
        assert_eq!(encoded, actual_hwp);
    }

    /// Tests that proof withing decoded HeaderWithProof matches expected value
    mod proof_decoding {
        use super::*;

        #[rstest::rstest]
        #[case(
            15539558,
            "15539558-cdf9ed89b0c43cda17398dc4da9cfc505e5ccd19f7c39e3b43474180f1051e01"
        )] // epoch 575
        #[case(
            15547621,
            "15547621-96a9313cd506e32893d46c82358569ad242bb32786bd5487833e0f77767aec2a"
        )] // epoch 576
        #[case(
            15555729,
            "15555729-c6fd396d54f61c6d0f1dd3653f81267b0378e9a0d638a229b24586d8fd0bc499"
        )] // epoch 577
        #[test]
        fn bellatrix(#[case] block_number: u64, #[case] file_path: &str) -> anyhow::Result<()> {
            let header_with_proof_yaml: serde_yaml::Value =
                read_yaml_test_file(PathBuf::from(TEST_DIR).join(format!("{block_number}.yaml")));
            let header_with_proof = HeaderWithProof::from_ssz_bytes(&Bytes::from_hex(
                header_with_proof_yaml["content_value"].as_str().unwrap(),
            )?)
            .unwrap();

            let expected_block_header_proof = BlockHeaderProof::HistoricalRoots(
                read_yaml_test_file(PathBuf::from(TEST_DIR).join(format!(
                    "block_proofs_bellatrix/beacon_block_proof-{file_path}.yaml"
                ))),
            );

            assert_eq!(header_with_proof.proof, expected_block_header_proof);
            Ok(())
        }

        #[rstest::rstest]
        #[case(17034870)] // epoch 759
        #[case(17042287)] // epoch 760
        #[case(17062257)] // epoch 762
        #[test]
        fn capella(#[case] block_number: u64) -> anyhow::Result<()> {
            let block_header_proof = BlockHeaderProof::HistoricalSummaries(read_yaml_test_file(
                PathBuf::from(TEST_DIR).join(format!(
                    "block_proofs_capella/beacon_block_proof-{block_number}.yaml"
                )),
            ));

            let header_with_proof_yaml: serde_yaml::Value =
                read_yaml_test_file(PathBuf::from(TEST_DIR).join(format!("{block_number}.yaml")));
            let header_with_proof = HeaderWithProof::from_ssz_bytes(&Bytes::from_hex(
                header_with_proof_yaml["content_value"].as_str().unwrap(),
            )?)
            .unwrap();

            assert_eq!(header_with_proof.proof, block_header_proof);
            Ok(())
        }
    }

    mod proof_generation {
        use super::*;

        #[rstest::rstest]
        #[case(
            15539558,
            4702208,
            "15539558-cdf9ed89b0c43cda17398dc4da9cfc505e5ccd19f7c39e3b43474180f1051e01"
        )] // epoch 575
        #[case(
            15547621,
            4710400,
            "15547621-96a9313cd506e32893d46c82358569ad242bb32786bd5487833e0f77767aec2a"
        )] // epoch 576
        #[case(
            15555729,
            4718592,
            "15555729-c6fd396d54f61c6d0f1dd3653f81267b0378e9a0d638a229b24586d8fd0bc499"
        )] // epoch 577
        #[test]
        fn bellatrix(#[case] block_number: u64, #[case] slot: u64, #[case] file_path: &str) {
            let expected_proof: BlockProofHistoricalRoots =
                read_yaml_test_file(PathBuf::from(TEST_DIR).join(format!(
                    "block_proofs_bellatrix/beacon_block_proof-{file_path}.yaml"
                )));

            let beacon_data_dir = PathBuf::from(TEST_DIR)
                .join("beacon_data")
                .join(format!("{block_number}"));
            let historical_batch_raw =
                read_bytes_from_tests_submodule(beacon_data_dir.join("historical_batch.ssz"))
                    .unwrap();
            let historical_batch = HistoricalBatch::from_ssz_bytes(&historical_batch_raw).unwrap();
            let block_raw =
                read_bytes_from_tests_submodule(beacon_data_dir.join("block.ssz")).unwrap();
            let block = BeaconBlockBellatrix::from_ssz_bytes(&block_raw).unwrap();
            let actual_proof = build_historical_roots_proof(slot, &historical_batch, &block);

            assert_eq!(expected_proof, actual_proof);
        }

        #[rstest::rstest]
        #[case(17034870, 6209538)] // epoch 759
        #[case(17042287, 6217730)] // epoch 760
        #[case(17062257, 6238210)] // epoch 762
        #[test]
        fn capella(#[case] block_number: u64, #[case] slot: u64) {
            let expected_proof: BlockProofHistoricalSummaries =
                read_yaml_test_file(PathBuf::from(TEST_DIR).join(format!(
                    "block_proofs_capella/beacon_block_proof-{block_number}.yaml"
                )));

            let beacon_data_dir = PathBuf::from(TEST_DIR)
                .join("beacon_data")
                .join(format!("{block_number}"));
            let beacon_state_raw =
                read_bytes_from_tests_submodule(beacon_data_dir.join("beacon_state.ssz")).unwrap();
            let beacon_state = BeaconStateCapella::from_ssz_bytes(&beacon_state_raw).unwrap();
            let block_raw =
                read_bytes_from_tests_submodule(beacon_data_dir.join("block.ssz")).unwrap();
            let block = BeaconBlockCapella::from_ssz_bytes(&block_raw).unwrap();
            let actual_proof =
                build_historical_summaries_proof(slot, &beacon_state.block_roots, &block);

            assert_eq!(expected_proof, actual_proof);
        }
    }

    fn read_yaml_test_file<T>(path: impl AsRef<Path>) -> T
    where
        T: for<'de> Deserialize<'de>,
    {
        let file_as_str = read_file_from_tests_submodule(path).unwrap();
        serde_yaml::from_str(&file_as_str).unwrap()
    }
}
