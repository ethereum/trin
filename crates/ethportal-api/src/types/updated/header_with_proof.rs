use alloy::primitives::B256;
use jsonrpsee::core::Serialize;
use serde::Deserialize;
use ssz::SszDecoderBuilder;
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, FixedVector, VariableList};

use crate::{
    types::{
        bytes::ByteList1024,
        execution::block_body::{MERGE_TIMESTAMP, SHANGHAI_TIMESTAMP},
    },
    Header,
};

/// The accumulator proof for the pre-merge blocks.
pub type HistoricalHashesAccumulatorProof = FixedVector<B256, typenum::U15>;

/// Proof that execution header root is part of BeaconBlock, post-Merge and pre-Capella
pub type BeaconBlockProofPreCapella = FixedVector<B256, typenum::U11>;
/// Proof that execution header root is part of BeaconBlock, post-Capella
pub type BeaconBlockProof = VariableList<B256, typenum::U12>;
/// Proof that BeaconBlockHeader root is part of HistoricalRoots
pub type HistoricalRootsProof = FixedVector<B256, typenum::U14>;
/// Proof that BeaconBlockHeader root is part of HistoricalSummaries
pub type HistoricalSummariesProof = FixedVector<B256, typenum::U13>;

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
    HistoricalHashesAccumulatorProof(HistoricalHashesAccumulatorProof),
    HistoricalRootsBlockProof(HistoricalRootsBlockProof),
    HistoricalSummariesBlockProof(HistoricalSummariesBlockProof),
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
            BlockHeaderProof::HistoricalHashesAccumulatorProof(
                HistoricalHashesAccumulatorProof::from_ssz_bytes(&proof)?,
            )
        } else if header.number <= SHANGHAI_TIMESTAMP {
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

impl ssz::Encode for BlockHeaderProof {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        match self {
            BlockHeaderProof::HistoricalHashesAccumulatorProof(proof) => {
                proof.ssz_append(buf);
            }
            BlockHeaderProof::HistoricalRootsBlockProof(proof) => {
                proof.ssz_append(buf);
            }
            BlockHeaderProof::HistoricalSummariesBlockProof(proof) => {
                proof.ssz_append(buf);
            }
        }
    }

    fn ssz_bytes_len(&self) -> usize {
        match self {
            BlockHeaderProof::HistoricalHashesAccumulatorProof(proof) => proof.ssz_bytes_len(),
            BlockHeaderProof::HistoricalRootsBlockProof(proof) => proof.ssz_bytes_len(),
            BlockHeaderProof::HistoricalSummariesBlockProof(proof) => proof.ssz_bytes_len(),
        }
    }
}

/// The struct holds a chain of proofs. This chain of proofs allows for verifying that an EL
/// `BlockHeader` is part of the canonical chain. The only requirement is having access to the
/// beacon chain `historical_roots`.
// Total size (8 + 1 + 3 + 1 + 14) * 32 bytes + 4 bytes = 868 bytes
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct HistoricalRootsBlockProof {
    pub beacon_block_proof: BeaconBlockProofPreCapella,
    pub beacon_block_root: B256,
    pub historical_roots_proof: HistoricalRootsProof,
    pub slot: u64,
}

/// The struct holds a chain of proofs. This chain of proofs allows for verifying that an EL
/// `BlockHeader` is part of the canonical chain. The only requirement is having access to the
/// beacon chain `historical_summaries`.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct HistoricalSummariesBlockProof {
    pub beacon_block_proof: BeaconBlockProof,
    pub beacon_block_root: B256,
    pub historical_summaries_proof: HistoricalSummariesProof,
    pub slot: u64,
}

pub mod ssz_header {

    use crate::{types::bytes::ByteList2048, Header};

    pub mod encode {
        use ssz::Encode;

        use super::*;

        pub fn is_ssz_fixed_len() -> bool {
            ByteList2048::is_ssz_fixed_len()
        }

        pub fn ssz_append(header: &Header, buf: &mut Vec<u8>) {
            let header = alloy::rlp::encode(header);
            ByteList2048::from(header).ssz_append(buf);
        }

        pub fn ssz_fixed_len() -> usize {
            ByteList2048::ssz_fixed_len()
        }

        pub fn ssz_bytes_len(header: &Header) -> usize {
            // The ssz encoded length is the same as rlp encoded length.
            alloy_rlp::Encodable::length(header)
        }
    }

    pub mod decode {
        use alloy_rlp::Decodable;
        use ssz::Decode;

        use super::*;

        pub fn is_ssz_fixed_len() -> bool {
            ByteList2048::is_ssz_fixed_len()
        }

        pub fn ssz_fixed_len() -> usize {
            ByteList2048::ssz_fixed_len()
        }

        pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Header, ssz::DecodeError> {
            let rlp_encoded_header = ByteList2048::from_ssz_bytes(bytes)?;
            Header::decode(&mut &*rlp_encoded_header).map_err(|_| {
                ssz::DecodeError::BytesInvalid("Unable to decode bytes into header.".to_string())
            })
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::fs;

    use serde_json::Value;
    use ssz::Decode;

    use super::*;
    use crate::utils::bytes::{hex_decode, hex_encode};

    #[test_log::test]
    fn decode_encode_headers_with_proof() {
        let file =
            fs::read_to_string("../validation/src/assets/fluffy/1000001-1000010.json").unwrap();
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
    fn decode_encode_more_headers_with_proofs(#[case] filename: &str) {
        let file = fs::read_to_string(format!("../validation/src/assets/fluffy/{filename}.yaml",))
            .unwrap();
        let yaml: serde_yaml::Value = serde_yaml::from_str(&file).unwrap();
        let actual_hwp = yaml.get("content_value").unwrap().as_str().unwrap();
        let hwp = HeaderWithProof::from_ssz_bytes(&hex_decode(actual_hwp).unwrap()).unwrap();
        assert_eq!(hwp.header.number, filename.parse::<u64>().unwrap());
        let encoded = hex_encode(ssz::Encode::as_ssz_bytes(&hwp));
        assert_eq!(encoded, actual_hwp);
    }
}
