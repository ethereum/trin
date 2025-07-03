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
        beacon_block::{BeaconBlockDeneb, BeaconBlockElectra},
        beacon_state::RootsPerHistoricalRoot,
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
        historical_batch.build_block_root_proof((slot % SLOTS_PER_HISTORICAL_ROOT) as usize),
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

/// Builds `BlockProofHistoricalSummariesCapella` for a given slot, from Capella `BeaconBlock`.
///
/// The `block_roots` represents the `block_roots` fields from `BeaconState`.
pub fn build_capella_historical_summaries_proof(
    slot: u64,
    block_roots: &RootsPerHistoricalRoot,
    beacon_block: &BeaconBlockCapella,
) -> BlockProofHistoricalSummariesCapella {
    let beacon_block_proof = build_merkle_proof_for_index(
        block_roots.clone(),
        (slot % SLOTS_PER_HISTORICAL_ROOT) as usize,
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

/// Builds `BlockProofHistoricalSummariesDeneb` for a given slot, from Deneb `BeaconBlock`.
///
/// The `block_roots` represents the `block_roots` fields from `BeaconState`.
pub fn build_deneb_historical_summaries_proof(
    slot: u64,
    block_roots: &RootsPerHistoricalRoot,
    beacon_block: &BeaconBlockDeneb,
) -> BlockProofHistoricalSummariesDeneb {
    let beacon_block_proof = build_merkle_proof_for_index(
        block_roots.clone(),
        (slot % SLOTS_PER_HISTORICAL_ROOT) as usize,
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

/// Builds `BlockProofHistoricalSummariesDeneb` for a given slot, from Electra `BeaconBlock`.
///
/// The `block_roots` represents the `block_roots` fields from `BeaconState`.
pub fn build_electra_historical_summaries_proof(
    slot: u64,
    block_roots: &RootsPerHistoricalRoot,
    beacon_block: &BeaconBlockElectra,
) -> BlockProofHistoricalSummariesDeneb {
    let beacon_block_proof = build_merkle_proof_for_index(
        block_roots.clone(),
        (slot % SLOTS_PER_HISTORICAL_ROOT) as usize,
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
    use std::{
        collections::HashMap,
        path::{Path, PathBuf},
    };

    use alloy::primitives::Bytes;
    use ssz::Encode;

    use super::*;
    use crate::{
        test_utils::{
            read_json_portal_spec_tests_file, read_ssz_portal_spec_tests_file,
            read_yaml_portal_spec_tests_file, types::ContentItem,
        },
        LegacyHistoryContentKey,
    };

    const TEST_DIR: &str = "tests/mainnet/history/headers_with_proof";
    fn test_path(path: impl AsRef<Path>) -> PathBuf {
        PathBuf::from(TEST_DIR).join(path)
    }

    #[test]
    fn decode_encode_headers_with_proof() {
        let all_test_data: HashMap<u64, ContentItem<LegacyHistoryContentKey>> =
            read_json_portal_spec_tests_file(test_path("1000001-1000010.json")).unwrap();
        for (block_number, test_data) in all_test_data {
            let header_with_proof = test_data.content_value_as_header_with_proof();
            assert_eq!(block_number, header_with_proof.header.number);

            let encoded = Bytes::from(header_with_proof.as_ssz_bytes());
            assert_eq!(encoded, test_data.raw_content_value);
        }
    }

    #[rstest::rstest]
    fn decode_encode_more_headers_with_proofs(
        #[values(
            1_000_010, 14_764_013, 15_537_392, 15_537_393, 15_537_394, 15_539_558, 15_547_621,
            15_555_729, 17_034_869, 17_034_870, 17_042_287, 17_062_257, 19_426_586, 19_426_587,
            22_162_263
        )]
        block_number: u64,
    ) {
        let test_data: ContentItem<LegacyHistoryContentKey> =
            read_yaml_portal_spec_tests_file(test_path(format!("{block_number}.yaml"))).unwrap();
        let header_with_proof = test_data.content_value_as_header_with_proof();
        assert_eq!(header_with_proof.header.number, block_number);

        let encoded = Bytes::from(header_with_proof.as_ssz_bytes());
        assert_eq!(encoded, test_data.raw_content_value);
    }

    /// Tests that decoded HeaderWithProof matches expected value
    mod proof_decoding {
        use super::*;

        #[rstest::rstest]
        fn bellatrix(
            #[values(15_537_394, 15_539_558, 15_547_621, 15_555_729, 17_034_869)] block_number: u64,
        ) -> anyhow::Result<()> {
            let test_data: ContentItem<LegacyHistoryContentKey> =
                read_yaml_portal_spec_tests_file(test_path(format!("{block_number}.yaml")))?;
            let header_with_proof = test_data.content_value_as_header_with_proof();

            let expected_block_header_proof =
                BlockHeaderProof::HistoricalRoots(read_yaml_portal_spec_tests_file(test_path(
                    format!("block_proofs_bellatrix/beacon_block_proof-{block_number}.yaml"),
                ))?);

            assert_eq!(header_with_proof.proof, expected_block_header_proof);
            Ok(())
        }

        #[rstest::rstest]
        fn capella(
            #[values(17_034_870, 17_042_287, 17_062_257, 19_426_586)] block_number: u64,
        ) -> anyhow::Result<()> {
            let test_data: ContentItem<LegacyHistoryContentKey> =
                read_yaml_portal_spec_tests_file(test_path(format!("{block_number}.yaml")))?;
            let header_with_proof = test_data.content_value_as_header_with_proof();

            let expected_block_header_proof = BlockHeaderProof::HistoricalSummariesCapella(
                read_yaml_portal_spec_tests_file(test_path(format!(
                    "block_proofs_capella/beacon_block_proof-{block_number}.yaml"
                )))?,
            );

            assert_eq!(header_with_proof.proof, expected_block_header_proof);
            Ok(())
        }

        #[rstest::rstest]
        fn deneb(#[values(19_426_587, 22_162_263)] block_number: u64) -> anyhow::Result<()> {
            let test_data: ContentItem<LegacyHistoryContentKey> =
                read_yaml_portal_spec_tests_file(test_path(format!("{block_number}.yaml")))?;
            let header_with_proof = test_data.content_value_as_header_with_proof();

            let expected_block_header_proof = BlockHeaderProof::HistoricalSummariesDeneb(
                read_yaml_portal_spec_tests_file(test_path(format!(
                    "block_proofs_deneb/beacon_block_proof-{block_number}.yaml"
                )))?,
            );

            assert_eq!(header_with_proof.proof, expected_block_header_proof);
            Ok(())
        }
    }

    /// Tests that generated header proof matches expected value
    mod proof_generation {
        use super::*;

        #[rstest::rstest]
        fn bellatrix(
            #[values(15_537_394, 15_539_558, 15_547_621, 15_555_729, 17_034_869)] block_number: u64,
        ) -> anyhow::Result<()> {
            let expected_proof: BlockProofHistoricalRoots =
                read_yaml_portal_spec_tests_file(test_path(format!(
                    "block_proofs_bellatrix/beacon_block_proof-{block_number}.yaml"
                )))?;

            let historical_batch = read_ssz_portal_spec_tests_file(test_path(format!(
                "beacon_data/{block_number}/historical_batch.ssz"
            )))?;
            let block = read_ssz_portal_spec_tests_file(test_path(format!(
                "beacon_data/{block_number}/block.ssz"
            )))?;
            let proof =
                build_historical_roots_proof(expected_proof.slot, &historical_batch, &block);

            assert_eq!(proof, expected_proof);
            Ok(())
        }

        #[rstest::rstest]
        fn capella(
            #[values(17_034_870, 17_042_287, 17_062_257, 19_426_586)] block_number: u64,
        ) -> anyhow::Result<()> {
            let expected_proof: BlockProofHistoricalSummariesCapella =
                read_yaml_portal_spec_tests_file(test_path(format!(
                    "block_proofs_capella/beacon_block_proof-{block_number}.yaml"
                )))?;

            let block_roots = read_ssz_portal_spec_tests_file(test_path(format!(
                "beacon_data/{block_number}/block_roots.ssz"
            )))?;
            let block = read_ssz_portal_spec_tests_file(test_path(format!(
                "beacon_data/{block_number}/block.ssz"
            )))?;
            let proof =
                build_capella_historical_summaries_proof(expected_proof.slot, &block_roots, &block);

            assert_eq!(proof, expected_proof);
            Ok(())
        }

        #[rstest::rstest]
        fn deneb(#[values(19_426_587, 22_162_263)] block_number: u64) -> anyhow::Result<()> {
            let expected_proof: BlockProofHistoricalSummariesDeneb =
                read_yaml_portal_spec_tests_file(test_path(format!(
                    "block_proofs_deneb/beacon_block_proof-{block_number}.yaml"
                )))?;

            let block_roots = read_ssz_portal_spec_tests_file(test_path(format!(
                "beacon_data/{block_number}/block_roots.ssz"
            )))?;
            let block = read_ssz_portal_spec_tests_file(test_path(format!(
                "beacon_data/{block_number}/block.ssz"
            )))?;
            let proof =
                build_deneb_historical_summaries_proof(expected_proof.slot, &block_roots, &block);

            assert_eq!(proof, expected_proof);
            Ok(())
        }
    }
}
