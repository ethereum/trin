use alloy::{consensus::Header, primitives::B256};
use alloy_hardforks::EthereumHardforks;
use jsonrpsee::core::Serialize;
use serde::Deserialize;
use ssz::SszDecoderBuilder;
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, FixedVector};
use tree_hash::TreeHash;

use crate::{
    consensus::{
        beacon_block::BeaconBlockDeneb, beacon_state::RootsPerHistoricalRoot,
        constants::SLOTS_PER_HISTORICAL_ROOT,
    },
    types::{
        bytes::ByteList1024,
        consensus::{
            beacon_block::{BeaconBlockBellatrix, BeaconBlockCapella},
            beacon_state::HistoricalBatch,
            proof::build_merkle_proof_for_index,
        },
        execution::ssz_header,
        network_spec::network_spec,
    },
};

/// The accumulator proof for EL BlockHeader for the pre-merge blocks.
pub type BlockProofHistoricalHashesAccumulator = FixedVector<B256, typenum::U15>;

/// Proof that EL block_hash is in BeaconBlock -> BeaconBlockBody -> ExecutionPayload
/// for Bellatrix until Deneb (exclusive)
pub type ExecutionBlockProofBellatrix = FixedVector<B256, typenum::U11>;
/// Proof that EL block_hash is in BeaconBlock -> BeaconBlockBody -> ExecutionPayload
/// for Deneb and onwards
pub type ExecutionBlockProofDeneb = FixedVector<B256, typenum::U12>;

/// Proof that BeaconBlock root is part of historical_roots and thus canonical
/// from TheMerge until Capella (exclusive)
pub type BeaconBlockProofHistoricalRoots = FixedVector<B256, typenum::U14>;
/// Proof that BeaconBlock root is part of historical_summaries and thus canonical
/// for Capella and onwards
pub type BeaconBlockProofHistoricalSummaries = FixedVector<B256, typenum::U13>;

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
    /// The block header proof for pre-Merge blocks
    HistoricalHashes(BlockProofHistoricalHashesAccumulator),
    /// The block header proof for Merge -> Capella blocks
    HistoricalRoots(BlockProofHistoricalRoots),
    /// The block header proof for Capella -> Deneb blocks
    HistoricalSummariesCapella(BlockProofHistoricalSummariesCapella),
    /// The block header proof for post-Deneb blocks
    HistoricalSummariesDeneb(BlockProofHistoricalSummariesDeneb),
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
        let proof = if network_spec().is_cancun_active_at_timestamp(header.timestamp) {
            BlockHeaderProof::HistoricalSummariesDeneb(
                BlockProofHistoricalSummariesDeneb::from_ssz_bytes(&proof)?,
            )
        } else if network_spec().is_shanghai_active_at_timestamp(header.timestamp) {
            BlockHeaderProof::HistoricalSummariesCapella(
                BlockProofHistoricalSummariesCapella::from_ssz_bytes(&proof)?,
            )
        } else if network_spec().is_paris_active_at_block(header.number) {
            BlockHeaderProof::HistoricalRoots(BlockProofHistoricalRoots::from_ssz_bytes(&proof)?)
        } else {
            BlockHeaderProof::HistoricalHashes(
                BlockProofHistoricalHashesAccumulator::from_ssz_bytes(&proof)?,
            )
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
            BlockHeaderProof::HistoricalHashes(proof) => proof.ssz_append(buf),
            BlockHeaderProof::HistoricalRoots(proof) => proof.ssz_append(buf),
            BlockHeaderProof::HistoricalSummariesCapella(proof) => proof.ssz_append(buf),
            BlockHeaderProof::HistoricalSummariesDeneb(proof) => proof.ssz_append(buf),
        }
    }

    fn ssz_bytes_len(&self) -> usize {
        match self {
            BlockHeaderProof::HistoricalHashes(proof) => proof.ssz_bytes_len(),
            BlockHeaderProof::HistoricalRoots(proof) => proof.ssz_bytes_len(),
            BlockHeaderProof::HistoricalSummariesCapella(proof) => proof.ssz_bytes_len(),
            BlockHeaderProof::HistoricalSummariesDeneb(proof) => proof.ssz_bytes_len(),
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
    pub execution_block_proof: ExecutionBlockProofBellatrix,
    /// Slot of BeaconBlock, used to calculate the historical_roots index
    pub slot: u64,
}

/// The struct holds a chain of proofs. This chain of proofs allows for verifying that an EL
/// `BlockHeader` is part of the canonical chain. The only requirement is having access to the
/// beacon chain `historical_summaries`.
///
/// Proof for EL BlockHeader for Capella until Deneb
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct BlockProofHistoricalSummariesCapella {
    /// Proof that the BeaconBlock is part of the historical_summaries
    /// and thus part of the canonical chain.
    pub beacon_block_proof: BeaconBlockProofHistoricalSummaries,
    /// hash_tree_root of BeaconBlock used to verify the proofs
    pub beacon_block_root: B256,
    /// Proof that EL BlockHash is part of the BeaconBlock
    pub execution_block_proof: ExecutionBlockProofBellatrix,
    /// Slot of BeaconBlock, used to calculate the historical_summaries index
    pub slot: u64,
}

/// The struct holds a chain of proofs. This chain of proofs allows for verifying that an EL
/// `BlockHeader` is part of the canonical chain. The only requirement is having access to the
/// beacon chain `historical_summaries`.
///
/// Proof for EL BlockHeader for Deneb and onwards
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct BlockProofHistoricalSummariesDeneb {
    /// Proof that the BeaconBlock is part of the historical_summaries
    /// and thus part of the canonical chain.
    pub beacon_block_proof: BeaconBlockProofHistoricalSummaries,
    /// hash_tree_root of BeaconBlock used to verify the proofs
    pub beacon_block_root: B256,
    /// Proof that EL BlockHash is part of the BeaconBlock
    pub execution_block_proof: ExecutionBlockProofDeneb,
    /// Slot of BeaconBlock, used to calculate the historical_summaries index
    pub slot: u64,
}

/// Builds `BlockProofHistoricalRoots` for a given slot.
pub fn build_historical_roots_proof(
    slot: u64,
    historical_batch: &HistoricalBatch,
    beacon_block: &BeaconBlockBellatrix,
) -> BlockProofHistoricalRoots {
    let beacon_block_proof = BeaconBlockProofHistoricalRoots::new(
        historical_batch.build_block_root_proof(slot as usize % SLOTS_PER_HISTORICAL_ROOT),
    )
    .expect("error creating BeaconBlockProofHistoricalRoots");

    // execution block proof
    let execution_block_proof =
        ExecutionBlockProofBellatrix::new(beacon_block.build_execution_block_hash_proof())
            .expect("error creating ExecutionBlockProofBellatrix");

    BlockProofHistoricalRoots {
        beacon_block_proof,
        beacon_block_root: beacon_block.tree_hash_root(),
        execution_block_proof,
        slot,
    }
}

/// Builds `BlockProofHistoricalSummariesCapella` for a given slot.
///
/// The `block_roots` represents the `block_roots` fields from `BeaconState`.
pub fn build_capella_historical_summaries_proof(
    slot: u64,
    block_roots: &RootsPerHistoricalRoot,
    beacon_block: &BeaconBlockCapella,
) -> BlockProofHistoricalSummariesCapella {
    let beacon_block_proof = build_merkle_proof_for_index(
        block_roots.clone(),
        slot as usize % SLOTS_PER_HISTORICAL_ROOT,
    );
    let beacon_block_proof = BeaconBlockProofHistoricalSummaries::new(beacon_block_proof)
        .expect("error creating BeaconBlockProofHistoricalSummaries");

    let execution_block_proof =
        ExecutionBlockProofBellatrix::new(beacon_block.build_execution_block_hash_proof())
            .expect("error creating ExecutionBlockProofBellatrix");

    BlockProofHistoricalSummariesCapella {
        beacon_block_proof,
        beacon_block_root: beacon_block.tree_hash_root(),
        execution_block_proof,
        slot,
    }
}

/// Builds `BlockProofHistoricalSummariesDeneb` for a given slot.
///
/// The `block_roots` represents the `block_roots` fields from `BeaconState`.
pub fn build_deneb_historical_summaries_proof(
    slot: u64,
    block_roots: &RootsPerHistoricalRoot,
    beacon_block: &BeaconBlockDeneb,
) -> BlockProofHistoricalSummariesDeneb {
    let beacon_block_proof = build_merkle_proof_for_index(
        block_roots.clone(),
        slot as usize % SLOTS_PER_HISTORICAL_ROOT,
    );
    let beacon_block_proof = BeaconBlockProofHistoricalSummaries::new(beacon_block_proof)
        .expect("error creating BeaconBlockProofHistoricalSummaries");

    let execution_block_proof =
        ExecutionBlockProofDeneb::new(beacon_block.build_execution_block_hash_proof())
            .expect("error creating ExecutionBlockProofDeneb");

    BlockProofHistoricalSummariesDeneb {
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
        test_utils::{read_bytes_from_tests_submodule, read_file_from_tests_submodule},
        utils::bytes::{hex_decode, hex_encode},
    };

    const TEST_DIR: &str = "tests/mainnet/history/headers_with_proof";

    #[test_log::test]
    fn decode_encode_headers_with_proof() {
        let path = PathBuf::from(TEST_DIR).join("1000001-1000010.json");
        let json: Value =
            serde_json::from_str(&read_file_from_tests_submodule(path).unwrap()).unwrap();
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
    #[case::block_1_000_010(1_000_010)]
    #[case::block_14_764_013(14_764_013)]
    #[case::block_15_537_392(15_537_392)]
    #[case::block_15_537_393(15_537_393)]
    #[case::block_15_539_558(15_539_558)]
    #[case::block_15_547_621(15_547_621)]
    #[case::block_15_555_729(15_555_729)]
    #[case::block_17_034_870(17_034_870)]
    #[case::block_17_042_287(17_042_287)]
    #[case::block_17_062_257(17_062_257)]
    #[case::block_22_162_263(22_162_263)]
    fn decode_encode_more_headers_with_proofs(#[case] block_number: u64) {
        let yaml: serde_yaml::Value = read_yaml_test_file(format!("{block_number}.yaml"));
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
        #[case::block_number_15_539_558(
            15_539_558,
            "15539558-cdf9ed89b0c43cda17398dc4da9cfc505e5ccd19f7c39e3b43474180f1051e01"
        )] // epoch 575
        #[case::block_number_15_547_621(
            15_547_621,
            "15547621-96a9313cd506e32893d46c82358569ad242bb32786bd5487833e0f77767aec2a"
        )] // epoch 576
        #[case::block_number_15_555_729(
            15_555_729,
            "15555729-c6fd396d54f61c6d0f1dd3653f81267b0378e9a0d638a229b24586d8fd0bc499"
        )] // epoch 577
        #[test]
        fn bellatrix(#[case] block_number: u64, #[case] file_path: &str) -> anyhow::Result<()> {
            let header_with_proof_yaml: serde_yaml::Value =
                read_yaml_test_file(format!("{block_number}.yaml"));
            let header_with_proof = HeaderWithProof::from_ssz_bytes(&Bytes::from_hex(
                header_with_proof_yaml["content_value"].as_str().unwrap(),
            )?)
            .unwrap();

            let expected_block_header_proof =
                BlockHeaderProof::HistoricalRoots(read_yaml_test_file(format!(
                    "block_proofs_bellatrix/beacon_block_proof-{file_path}.yaml"
                )));

            assert_eq!(header_with_proof.proof, expected_block_header_proof);
            Ok(())
        }

        #[rstest::rstest]
        #[case::block_number_17_034_870(17_034_870)] // epoch 759
        #[case::block_number_17_042_287(17_042_287)] // epoch 760
        #[case::block_number_17_062_257(17_062_257)] // epoch 762
        #[test]
        fn capella(#[case] block_number: u64) -> anyhow::Result<()> {
            let block_header_proof =
                BlockHeaderProof::HistoricalSummariesCapella(read_yaml_test_file(format!(
                    "block_proofs_capella/beacon_block_proof-{block_number}.yaml"
                )));

            let header_with_proof_yaml: serde_yaml::Value =
                read_yaml_test_file(format!("{block_number}.yaml"));
            let header_with_proof = HeaderWithProof::from_ssz_bytes(&Bytes::from_hex(
                header_with_proof_yaml["content_value"].as_str().unwrap(),
            )?)
            .unwrap();

            assert_eq!(header_with_proof.proof, block_header_proof);
            Ok(())
        }

        #[rstest::rstest]
        #[case::block_number_22_162_263(22_162_263)]
        #[test]
        fn deneb(#[case] block_number: u64) -> anyhow::Result<()> {
            let block_header_proof =
                BlockHeaderProof::HistoricalSummariesDeneb(read_yaml_test_file(format!(
                    "block_proofs_deneb/beacon_block_proof-{block_number}.yaml"
                )));

            let header_with_proof_yaml: serde_yaml::Value =
                read_yaml_test_file(format!("{block_number}.yaml"));
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
        #[case::block_number_15_539_558(
            15_539_558,
            4_702_208,
            "15539558-cdf9ed89b0c43cda17398dc4da9cfc505e5ccd19f7c39e3b43474180f1051e01"
        )] // epoch 575
        #[case::block_number_15_547_621(
            15_547_621,
            4_710_400,
            "15547621-96a9313cd506e32893d46c82358569ad242bb32786bd5487833e0f77767aec2a"
        )] // epoch 576
        #[case::block_number_15_555_729(
            15_555_729,
            4_718_592,
            "15555729-c6fd396d54f61c6d0f1dd3653f81267b0378e9a0d638a229b24586d8fd0bc499"
        )] // epoch 577
        #[test]
        fn bellatrix(#[case] block_number: u64, #[case] slot: u64, #[case] file_path: &str) {
            let expected_proof: BlockProofHistoricalRoots = read_yaml_test_file(format!(
                "block_proofs_bellatrix/beacon_block_proof-{file_path}.yaml"
            ));

            let historical_batch =
                read_ssz_test_file(format!("beacon_data/{block_number}/historical_batch.ssz"));
            let block = read_ssz_test_file(format!("beacon_data/{block_number}/block.ssz"));
            let actual_proof = build_historical_roots_proof(slot, &historical_batch, &block);

            assert_eq!(expected_proof, actual_proof);
        }

        #[rstest::rstest]
        #[case::block_number_17_034_870(17_034_870, 6_209_538)] // epoch 759
        #[case::block_number_17_042_287(17_042_287, 6_217_730)] // epoch 760
        #[case::block_number_17_062_257(17_062_257, 6_238_210)] // epoch 762
        #[test]
        fn capella(#[case] block_number: u64, #[case] slot: u64) {
            let expected_proof: BlockProofHistoricalSummariesCapella = read_yaml_test_file(
                format!("block_proofs_capella/beacon_block_proof-{block_number}.yaml"),
            );

            let block_roots =
                read_ssz_test_file(format!("beacon_data/{block_number}/block_roots.ssz"));
            let block = read_ssz_test_file(format!("beacon_data/{block_number}/block.ssz"));
            let actual_proof = build_capella_historical_summaries_proof(slot, &block_roots, &block);

            assert_eq!(expected_proof, actual_proof);
        }

        #[rstest::rstest]
        #[case::block_number_22162263(22162263, 11378687)]
        #[test]
        fn deneb(#[case] block_number: u64, #[case] slot: u64) {
            let expected_proof: BlockProofHistoricalSummariesDeneb = read_yaml_test_file(format!(
                "block_proofs_deneb/beacon_block_proof-{block_number}.yaml"
            ));

            let block_roots =
                read_ssz_test_file(format!("beacon_data/{block_number}/block_roots.ssz"));
            let block = read_ssz_test_file(format!("beacon_data/{block_number}/block.ssz"));
            let actual_proof = build_deneb_historical_summaries_proof(slot, &block_roots, &block);

            assert_eq!(expected_proof, actual_proof);
        }
    }

    /// Reads and deserializes the yaml test file.
    ///
    /// The `path` argument is relative to [TEST_DIR].
    fn read_yaml_test_file<T>(path: impl AsRef<Path>) -> T
    where
        T: for<'de> Deserialize<'de>,
    {
        let path = PathBuf::from(TEST_DIR).join(path);
        serde_yaml::from_str(&read_file_from_tests_submodule(path).unwrap()).unwrap()
    }

    /// Reads and decodes the ssz test file.
    ///
    /// The `path` argument is relative to [TEST_DIR].
    fn read_ssz_test_file<T: Decode>(path: impl AsRef<Path>) -> T {
        let path = PathBuf::from(TEST_DIR).join(path);
        T::from_ssz_bytes(&read_bytes_from_tests_submodule(path).unwrap()).unwrap()
    }
}
