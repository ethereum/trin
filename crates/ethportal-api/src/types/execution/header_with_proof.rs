use alloy::{consensus::Header, primitives::B256};
use jsonrpsee::core::Serialize;
use serde::Deserialize;
use ssz::SszDecoderBuilder;
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, FixedVector};
use tree_hash::TreeHash;

use crate::{
    consensus::{
        beacon_block::BeaconBlockDeneb, beacon_state::HashesPerHistoricalRoot,
        proof::build_merkle_proof_for_index,
    },
    types::{
        bytes::ByteList1024,
        consensus::{
            beacon_block::{BeaconBlockBellatrix, BeaconBlockCapella},
            beacon_state::HistoricalBatch,
        },
        execution::ssz_header,
    },
};

/// The timestamp of the first Merge block (block number: 15537394)
pub const MERGE_TIMESTAMP: u64 = 1663224179;

/// The timestamp of the first Shapella (Shanghai-Capella) slot.
///
/// - Slot: 6209536
/// - Epoch: 194048
/// - Block number: 17034870
///     - Note that frst Shapella block is created at slot 6209538 (timestamp: 1681338479)
pub const SHAPELLA_TIMESTAMP: u64 = 1681338455;

/// The timestamp of the first Dencun (Cancun-Deneb) slot.
///
/// - Slot: 8626176
/// - Epoch: 269568
/// - Block number: 19426587
pub const DENCUN_TIMESTAMP: u64 = 1710338135;

/// The accumulator proof for EL BlockHeader for the pre-merge blocks.
pub type BlockProofHistoricalHashesAccumulator = FixedVector<B256, typenum::U15>;

/// Proof that EL block_hash is in BeaconBlock -> BeaconBlockBody -> ExecutionPayload
/// for Bellatrix until Deneb (exclusive)
pub type ExecutionBlockProofBellatrix = FixedVector<B256, typenum::U11>;
/// Proof that EL block_hash is in BeaconBlock -> BeaconBlockBody -> ExecutionPayload
/// for Deneb and onwards
pub type ExecutionBlockProofDeneb = FixedVector<B256, typenum::U12>;
/// Proof that BeaconBlock root is part of historical_summaries and thus canonical
/// for Capella and onwards
pub type BeaconBlockProofHistoricalSummaries = FixedVector<B256, typenum::U13>;
/// Proof that BeaconBlock root is part of historical_roots and thus canonical
/// from TheMerge until Capella fork.
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
    HistoricalSummariesCapella(BlockProofHistoricalSummariesCapella),
    // Post-Capella
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
        let proof = match header.timestamp {
            0..MERGE_TIMESTAMP => BlockHeaderProof::HistoricalHashes(
                BlockProofHistoricalHashesAccumulator::from_ssz_bytes(&proof)?,
            ),
            MERGE_TIMESTAMP..SHAPELLA_TIMESTAMP => BlockHeaderProof::HistoricalRoots(
                BlockProofHistoricalRoots::from_ssz_bytes(&proof)?,
            ),
            SHAPELLA_TIMESTAMP..DENCUN_TIMESTAMP => BlockHeaderProof::HistoricalSummariesCapella(
                BlockProofHistoricalSummariesCapella::from_ssz_bytes(&proof)?,
            ),
            DENCUN_TIMESTAMP.. => BlockHeaderProof::HistoricalSummariesDeneb(
                BlockProofHistoricalSummariesDeneb::from_ssz_bytes(&proof)?,
            ),
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
            BlockHeaderProof::HistoricalSummariesCapella(proof) => {
                proof.ssz_append(buf);
            }
            BlockHeaderProof::HistoricalSummariesDeneb(proof) => {
                proof.ssz_append(buf);
            }
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

pub fn build_historical_roots_proof(
    slot: u64,
    historical_batch: &HistoricalBatch,
    beacon_block: BeaconBlockBellatrix,
) -> BlockProofHistoricalRoots {
    let beacon_block_proof = historical_batch.build_block_root_proof(slot % 8192);

    // execution block proof
    let mut execution_block_hash_proof = beacon_block.body.build_execution_block_hash_proof();
    let body_root_proof = beacon_block.build_body_root_proof();
    execution_block_hash_proof.extend(body_root_proof);

    BlockProofHistoricalRoots {
        beacon_block_proof: beacon_block_proof.into(),
        beacon_block_root: beacon_block.tree_hash_root(),
        execution_block_proof: execution_block_hash_proof.into(),
        slot,
    }
}

pub fn build_capella_historical_summaries_proof(
    slot: u64,
    block_roots: &HashesPerHistoricalRoot,
    beacon_block: BeaconBlockCapella,
) -> BlockProofHistoricalSummariesCapella {
    // beacon block proof
    let block_root_proof = build_root_proof(block_roots, slot as usize % 8192);
    let beacon_block_proof: BeaconBlockProofHistoricalSummaries = block_root_proof.into();

    // execution block proof
    let mut execution_block_hash_proof = beacon_block.body.build_execution_block_hash_proof();
    let body_root_proof = beacon_block.build_body_root_proof();
    execution_block_hash_proof.extend(body_root_proof);

    BlockProofHistoricalSummariesCapella {
        beacon_block_proof,
        beacon_block_root: beacon_block.tree_hash_root(),
        execution_block_proof: execution_block_hash_proof.into(),
        slot,
    }
}

pub fn build_deneb_historical_summaries_proof(
    slot: u64,
    block_roots: &HashesPerHistoricalRoot,
    beacon_block: BeaconBlockDeneb,
) -> BlockProofHistoricalSummariesDeneb {
    // beacon block proof
    let block_root_proof = build_root_proof(block_roots, slot as usize % 8192);
    let beacon_block_proof: BeaconBlockProofHistoricalSummaries = block_root_proof.into();

    // execution block proof
    let mut execution_block_hash_proof = beacon_block.body.build_execution_block_hash_proof();
    let body_root_proof = beacon_block.build_body_root_proof();
    execution_block_hash_proof.extend(body_root_proof);

    BlockProofHistoricalSummariesDeneb {
        beacon_block_proof,
        beacon_block_root: beacon_block.tree_hash_root(),
        execution_block_proof: execution_block_hash_proof.into(),
        slot,
    }
}

pub fn build_root_proof(
    block_roots: &HashesPerHistoricalRoot,
    block_root_index: usize,
) -> Vec<B256> {
    let leaves: Vec<[u8; 32]> = block_roots
        .iter()
        .map(|root| root.tree_hash_root().0)
        .collect();
    build_merkle_proof_for_index(leaves, block_root_index)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use serde_json::Value;
    use ssz::Decode;

    use super::*;
    use crate::{
        test_utils::{read_bytes_from_tests_submodule, read_file_from_tests_submodule},
        utils::bytes::{hex_decode, hex_encode},
    };

    #[test_log::test]
    fn decode_encode_headers_with_proof() {
        let file = read_file_from_tests_submodule(
            "tests/mainnet/history/headers_with_proof/1000001-1000010.json",
        )
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
    #[case("1000010")]
    #[case("14764013")]
    #[case("15537392")]
    #[case("15537393")]
    #[case("15539558")]
    #[case("15547621")]
    #[case("15555729")]
    #[case("17034870")]
    #[case("17042287")]
    #[case("17062257")]
    #[case("22162263")]
    fn decode_encode_more_headers_with_proofs(#[case] filename: &str) {
        let file = read_file_from_tests_submodule(format!(
            "tests/mainnet/history/headers_with_proof/{filename}.yaml"
        ))
        .unwrap();
        let yaml: serde_yaml::Value = serde_yaml::from_str(&file).unwrap();
        let actual_hwp = yaml.get("content_value").unwrap().as_str().unwrap();
        let hwp = HeaderWithProof::from_ssz_bytes(&hex_decode(actual_hwp).unwrap()).unwrap();
        assert_eq!(hwp.header.number, filename.parse::<u64>().unwrap());
        let encoded = hex_encode(ssz::Encode::as_ssz_bytes(&hwp));
        assert_eq!(encoded, actual_hwp);
    }

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
    #[tokio::test]
    async fn historical_roots_proof_generation(
        #[case] block_number: u64,
        #[case] slot: u64,
        #[case] file_path: &str,
    ) {
        let test_vector = read_file_from_tests_submodule(format!(
            "tests/mainnet/history/headers_with_proof/block_proofs_bellatrix/beacon_block_proof-{file_path}.yaml"
        ))
        .unwrap();
        let expected_proof: BlockProofHistoricalRoots = serde_yaml::from_str(&test_vector).unwrap();

        let test_assets_dir =
            format!("tests/mainnet/history/headers_with_proof/beacon_data/{block_number}");
        let historical_batch_raw =
            read_bytes_from_tests_submodule(format!("{test_assets_dir}/historical_batch.ssz",))
                .unwrap();
        let historical_batch = HistoricalBatch::from_ssz_bytes(&historical_batch_raw).unwrap();
        let block_raw =
            read_bytes_from_tests_submodule(format!("{test_assets_dir}/block.ssz",)).unwrap();
        let block = BeaconBlockBellatrix::from_ssz_bytes(&block_raw).unwrap();
        let actual_proof = build_historical_roots_proof(slot, &historical_batch, block);

        assert_eq!(expected_proof, actual_proof);
    }

    #[rstest::rstest]
    #[case(17034870, 6209538)] // epoch 759
    #[case(17042287, 6217730)] // epoch 760
    #[case(17062257, 6238210)] // epoch 762
    #[tokio::test]
    async fn pre_deneb_historical_summaries_generation(
        #[case] block_number: u64,
        #[case] slot: u64,
    ) {
        let test_vector = read_file_from_tests_submodule(format!(
            "tests/mainnet/history/headers_with_proof/block_proofs_capella/beacon_block_proof-{block_number}.yaml",
        ))
        .unwrap();
        let expected_proof: BlockProofHistoricalSummariesCapella =
            serde_yaml::from_str(&test_vector).unwrap();

        let test_assets_dir =
            format!("tests/mainnet/history/headers_with_proof/beacon_data/{block_number}");
        let beacon_state_raw =
            read_bytes_from_tests_submodule(format!("{test_assets_dir}/block_roots.ssz",)).unwrap();
        let block_roots = HashesPerHistoricalRoot::from_ssz_bytes(&beacon_state_raw).unwrap();
        let block_raw =
            read_bytes_from_tests_submodule(format!("{test_assets_dir}/block.ssz",)).unwrap();
        let block = BeaconBlockCapella::from_ssz_bytes(&block_raw).unwrap();
        let actual_proof = build_capella_historical_summaries_proof(slot, &block_roots, block);

        assert_eq!(expected_proof, actual_proof);
    }

    #[rstest::rstest]
    #[case(22162263, 11378687)]
    #[tokio::test]
    async fn post_deneb_historical_summaries_generation(
        #[case] block_number: u64,
        #[case] slot: u64,
    ) {
        let test_vector = read_file_from_tests_submodule(format!(
            "tests/mainnet/history/headers_with_proof/block_proofs_deneb/beacon_block_proof-{block_number}.yaml",
        ))
        .unwrap();
        let expected_proof: BlockProofHistoricalSummariesDeneb =
            serde_yaml::from_str(&test_vector).unwrap();

        let test_assets_dir =
            format!("tests/mainnet/history/headers_with_proof/beacon_data/{block_number}");
        let beacon_state_raw =
            read_bytes_from_tests_submodule(format!("{test_assets_dir}/block_roots.ssz",)).unwrap();
        let block_roots = HashesPerHistoricalRoot::from_ssz_bytes(&beacon_state_raw).unwrap();
        let block_raw =
            read_bytes_from_tests_submodule(format!("{test_assets_dir}/block.ssz",)).unwrap();
        let block = BeaconBlockDeneb::from_ssz_bytes(&block_raw).unwrap();
        let actual_proof = build_deneb_historical_summaries_proof(slot, &block_roots, block);

        assert_eq!(expected_proof, actual_proof);
    }
}
