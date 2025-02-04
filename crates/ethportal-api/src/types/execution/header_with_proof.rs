use alloy::{primitives::B256, rlp::Decodable};
use jsonrpsee::core::Serialize;
use serde::Deserialize;
use ssz::{Encode, SszDecoderBuilder, SszEncoder};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, FixedVector};

use crate::{
    types::{
        bytes::{ByteList1024, ByteList2048},
        execution::block_body::{MERGE_TIMESTAMP, SHANGHAI_TIMESTAMP},
    },
    Header,
};
/// A block header with accumulator proof.
/// Type definition:
/// https://github.com/status-im/nimbus-eth1/blob/master/fluffy/network/history/history_content.nim#L136
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct HeaderWithProof {
    pub header: Header,
    pub proof: BlockHeaderProof,
}

impl ssz::Encode for HeaderWithProof {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let header = alloy::rlp::encode(&self.header);
        let header = ByteList2048::from(header);
        let proof = ByteList1024::from(self.proof.as_ssz_bytes());
        let offset =
            <ByteList2048 as Encode>::ssz_fixed_len() + <ByteList1024 as Encode>::ssz_fixed_len();
        let mut encoder = SszEncoder::container(buf, offset);
        encoder.append(&header);
        encoder.append(&proof);
        encoder.finalize();
    }

    fn ssz_bytes_len(&self) -> usize {
        let header = alloy::rlp::encode(&self.header);
        let header = ByteList2048::from(header);
        header.len() + self.proof.ssz_bytes_len()
    }
}

#[derive(Debug, Clone, PartialEq, Decode, Encode, Deserialize)]
#[ssz(enum_behaviour = "transparent")]
// Ignore clippy here, since "box"-ing the accumulator proof breaks the Decode trait
#[allow(clippy::large_enum_variant)]
pub enum BlockHeaderProof {
    // xxx: we need to update these names to match the spec...
    PreMergeAccumulatorProof(PreMergeAccumulatorProof),
    HistoricalRootsBlockProof(HistoricalRootsBlockProof),
    HistoricalSummariesBlockProof(HistoricalSummariesBlockProof),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreMergeAccumulatorProof {
    pub proof: [B256; 15],
}

impl ssz::Decode for HeaderWithProof {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);

        builder.register_type::<ByteList2048>()?;
        builder.register_type::<ByteList1024>()?;

        let mut decoder = builder.build()?;

        let header_rlp: Vec<u8> = decoder.decode_next()?;
        let proof: Vec<u8> = decoder.decode_next()?;
        let header: Header = Decodable::decode(&mut header_rlp.as_slice()).map_err(|_| {
            ssz::DecodeError::BytesInvalid("Unable to decode bytes into header.".to_string())
        })?;
        let proof = if header.timestamp < MERGE_TIMESTAMP {
            BlockHeaderProof::PreMergeAccumulatorProof(PreMergeAccumulatorProof::from_ssz_bytes(
                &proof,
            )?)
        } else if header.number < SHANGHAI_TIMESTAMP {
            BlockHeaderProof::HistoricalRootsBlockProof(HistoricalRootsBlockProof::from_ssz_bytes(
                &proof,
            )?)
        } else {
            BlockHeaderProof::HistoricalSummariesBlockProof(
                HistoricalSummariesBlockProof::from_ssz_bytes(&proof)?,
            )
        };
        Ok(Self { header, proof })
    }
}

impl ssz::Decode for PreMergeAccumulatorProof {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let vec: Vec<[u8; 32]> = Vec::from_ssz_bytes(bytes)?;
        let mut proof: [B256; 15] = [B256::ZERO; 15];
        let raw_proof: [[u8; 32]; 15] = vec
            .try_into()
            .map_err(|_| ssz::DecodeError::BytesInvalid("Invalid proof length".to_string()))?;
        for (idx, val) in raw_proof.iter().enumerate() {
            proof[idx] = B256::from_slice(val);
        }
        Ok(Self { proof })
    }
}

impl ssz::Encode for PreMergeAccumulatorProof {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let offset = self.ssz_bytes_len();
        let mut encoder = SszEncoder::container(buf, offset);

        for proof in self.proof {
            encoder.append(&proof);
        }
        encoder.finalize();
    }

    fn ssz_bytes_len(&self) -> usize {
        <B256 as Encode>::ssz_fixed_len() * 15
    }
}

/// Proof that execution header root is part of BeaconBlock
pub type BeaconBlockProof = FixedVector<B256, typenum::U11>;
/// Proof that BeaconBlockHeader root is part of HistoricalRoots
pub type HistoricalRootsProof = FixedVector<B256, typenum::U14>;
/// Proof that BeaconBlockHeader root is part of HistoricalSummaries
pub type HistoricalSummariesProof = FixedVector<B256, typenum::U13>;

/// The struct holds a chain of proofs. This chain of proofs allows for verifying that an EL
/// `BlockHeader` is part of the canonical chain. The only requirement is having access to the
/// beacon chain `historical_roots`.
// Total size (8 + 1 + 3 + 1 + 14) * 32 bytes + 4 bytes = 868 bytes
#[derive(Debug, Clone, PartialEq, Encode, Decode, Serialize, Deserialize)]
pub struct HistoricalRootsBlockProof {
    pub beacon_block_proof: BeaconBlockProof,
    pub beacon_block_root: B256,
    pub historical_roots_proof: HistoricalRootsProof,
    pub slot: u64,
}

/// The struct holds a chain of proofs. This chain of proofs allows for verifying that an EL
/// `BlockHeader` is part of the canonical chain. The only requirement is having access to the
/// beacon chain `historical_summaries`.
#[derive(Debug, Clone, PartialEq, Encode, Decode, Serialize, Deserialize)]
pub struct HistoricalSummariesBlockProof {
    pub beacon_block_proof: BeaconBlockProof,
    pub beacon_block_root: B256,
    pub historical_summaries_proof: HistoricalSummariesProof,
    pub slot: u64,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {

    use serde_json::Value;
    use ssz::Decode;

    use super::*;
    use crate::{
        test_utils::read_file_from_tests_submodule,
        utils::bytes::{hex_decode, hex_encode},
    };

    #[test_log::test]
    fn decode_encode_header_with_proofs() {
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
            let encoded = hex_encode(hwp.as_ssz_bytes());
            assert_eq!(encoded, actual_hwp);
        }
    }

    #[rstest::rstest]
    #[case("1000010")]
    #[case("14764013")]
    #[case("15537392")]
    #[case("15537393")]
    fn decode_encode_more_headers_with_proofs(#[case] filename: &str) {
        let file = fs::read_to_string(format!(
            "../../portal-spec-tests/tests/mainnet/history/headers_with_proof/{filename}.yaml",
        ))
        .unwrap();
        let yaml: serde_yaml::Value = serde_yaml::from_str(&file).unwrap();
        let actual_hwp = yaml.get("content_value").unwrap().as_str().unwrap();
        let hwp = HeaderWithProof::from_ssz_bytes(&hex_decode(actual_hwp).unwrap()).unwrap();
        assert_eq!(hwp.header.number, filename.parse::<u64>().unwrap());
        let encoded = hex_encode(hwp.as_ssz_bytes());
        assert_eq!(encoded, actual_hwp);
    }
}
